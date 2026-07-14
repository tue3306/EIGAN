"""Guardrail de escopo — regra inegociável do produto.

Nenhum scan ativo ocorre contra um alvo que não esteja explicitamente
autorizado no ``scope.yaml``. Esta é a camada de defesa legal do produto
(CLAUDE.md §3.1): alvos fora do escopo são bloqueados *por padrão*.

Faz parte do domínio/segurança — sem I/O de rede, apenas decisão pura sobre
autorização, para ser trivialmente testável.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..perspective import Perspective, extract_host, target_allowed, validate_target


class ScopeViolation(Exception):
    """Lançada quando um alvo fora do escopo autorizado é submetido."""


class InvalidTarget(ScopeViolation):
    """Alvo malformado (forma inválida: começa com '-', contém espaço/controle).

    Subclasse de :class:`ScopeViolation` para que todo handler que já barra
    violação de escopo também barre um alvo malformado — nunca chega a um runner
    (defesa em profundidade contra *argument injection*, §5)."""


class PerspectiveViolation(ScopeViolation):
    """Alvo incompatível com a perspectiva do job (ex.: IP privado em EXTERNAL,
    IP público em INTERNAL). Subclasse de :class:`ScopeViolation` para que quem
    já captura violação de escopo também barre incompatibilidade de perspectiva."""


@dataclass
class Scope:
    """Escopo autorizado.

    Há dois modos de uso, deliberadamente distintos:

    * **Trava dura (opt-in)** — carregada de um ``scope.yaml`` explícito (``--scope``):
      ``enforce_membership=True``. O alvo PRECISA pertencer a ``hosts``. É a trava
      para times/CI que querem uma allowlist rígida por engajamento.
    * **Efêmero (default do produto)** — construído a partir dos próprios alvos
      informados, com ``enforce_membership=False``: a autorização é o *consent gate*
      inline (o usuário afirma que tem permissão), não uma lista em arquivo. Foi a
      fricção que travava scans legítimos (ex.: uma URL não casava consigo mesma).

    ``hosts`` aceita IPs, hostnames e redes CIDR (URLs são normalizadas para o host).
    """

    authorized: bool = False
    engagement: str = ""
    hosts: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    perspective: Perspective = Perspective.UNIFIED
    # Só a trava dura por arquivo (scope.yaml explícito) exige pertencimento à lista.
    # No modo efêmero o consent gate é a autorização — não uma allowlist.
    enforce_membership: bool = True

    def __post_init__(self) -> None:
        # Normaliza para o host (tira esquema/porta/caminho de URLs) — assim uma
        # entrada como "https://alvo/" casa com o alvo "alvo" e vice-versa.
        self.hosts = [extract_host(str(h)) for h in self.hosts]
        self.exclude = [extract_host(str(h)) for h in self.exclude]

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        data = yaml.safe_load(Path(path).read_text()) or {}
        return cls(
            authorized=bool(data.get("authorized", False)),
            engagement=str(data.get("engagement", "")),
            hosts=[str(h) for h in data.get("hosts", [])],
            exclude=[str(h) for h in data.get("exclude", [])],
            perspective=Perspective(str(data.get("perspective", "unified")).lower()),
            enforce_membership=True,  # arquivo explícito = trava dura por lista
        )

    @staticmethod
    def _target_host(target: str) -> str:
        """Extrai o host de um alvo que pode ser IP, hostname ou URL."""
        return extract_host(target)

    @staticmethod
    def _matches(host: str, pattern: str) -> bool:
        host = host.strip().lower()
        pattern = pattern.strip().lower()
        if host == pattern:
            return True
        # CIDR / IP-em-rede
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            return ipaddress.ip_address(host) in net
        except ValueError:
            pass
        # wildcard de subdomínio: "*.example.com"
        if pattern.startswith("*."):
            return host == pattern[2:] or host.endswith(pattern[1:])
        return False

    def contains(self, target: str) -> bool:
        host = self._target_host(target)
        if any(self._matches(host, ex) for ex in self.exclude):
            return False
        return any(self._matches(host, h) for h in self.hosts)

    def enforce(
        self, target: str, *, perspective: Perspective | None = None, override: bool = False
    ) -> None:
        """Bloqueia por padrão. Ordem de verificação (todas obrigatórias):

        1. escopo autorizado (`authorized: true`);
        2. compatibilidade alvo × perspectiva (público×privado) — antes de tudo;
        3. alvo contido no escopo declarado.

        ``override`` libera a regra de perspectiva (nº 2) explicitamente; nunca
        libera autorização nem pertencimento ao escopo.
        """
        persp = perspective or self.perspective

        # 0. Forma do alvo (defesa em profundidade, §5): barra antes de tudo para
        #    que um alvo malformado nunca alcance o build_args de um runner.
        try:
            validate_target(target)
        except ValueError as exc:
            raise InvalidTarget(str(exc)) from exc

        # 0b. Metadata de nuvem (169.254.169.254 etc.) NUNCA é alvo legítimo — só
        #     pivô de SSRF. Bloqueado SEMPRE, independente de perspectiva/override
        #     (§3.2/§4/ADR-0015). O redirect/DNS-rebinding é fechado no cliente HTTP.
        from . import ssrf

        if ssrf.is_metadata_literal(extract_host(target)):
            raise ScopeViolation(
                f"Endereço de metadata de nuvem bloqueado (SSRF): {target!r}. "
                "Não é alvo legítimo de scanner ativo."
            )

        if not self.authorized:
            raise ScopeViolation(
                "Escopo não autorizado: defina 'authorized: true' no scope.yaml "
                "apenas se você tem permissão explícita para testar estes alvos."
            )

        ok, reason = target_allowed(persp, target, override=override)
        if not ok:
            raise PerspectiveViolation(f"Bloqueado por regra de perspectiva: {reason}")

        # Pertencimento à lista só é exigido pela trava dura por arquivo (opt-in).
        # No modo efêmero (default), a autorização é o consent gate inline — não uma
        # allowlist —, então não bloqueamos aqui.
        if self.enforce_membership and not self.contains(target):
            raise ScopeViolation(
                f"Alvo fora do escopo autorizado: {target!r}. "
                "Adicione-o a 'hosts' no scope.yaml (com autorização real)."
            )
