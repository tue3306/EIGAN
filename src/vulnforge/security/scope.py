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

from ..perspective import Perspective, extract_host, target_allowed


class ScopeViolation(Exception):
    """Lançada quando um alvo fora do escopo autorizado é submetido."""


class PerspectiveViolation(ScopeViolation):
    """Alvo incompatível com a perspectiva do job (ex.: IP privado em EXTERNAL,
    IP público em INTERNAL). Subclasse de :class:`ScopeViolation` para que quem
    já captura violação de escopo também barre incompatibilidade de perspectiva."""


@dataclass
class Scope:
    """Escopo autorizado carregado de ``scope.yaml``.

    ``hosts`` aceita IPs, hostnames e redes CIDR. ``authorized`` deve ser True
    explicitamente — é o *consent gate* em disco: sem ele, tudo é bloqueado.
    """

    authorized: bool = False
    engagement: str = ""
    hosts: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    perspective: Perspective = Perspective.EXTERNAL

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        data = yaml.safe_load(Path(path).read_text()) or {}
        return cls(
            authorized=bool(data.get("authorized", False)),
            engagement=str(data.get("engagement", "")),
            hosts=[str(h) for h in data.get("hosts", [])],
            exclude=[str(h) for h in data.get("exclude", [])],
            perspective=Perspective(str(data.get("perspective", "external")).lower()),
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

    def enforce(self, target: str, *, perspective: Perspective | None = None,
                override: bool = False) -> None:
        """Bloqueia por padrão. Ordem de verificação (todas obrigatórias):

        1. escopo autorizado (`authorized: true`);
        2. compatibilidade alvo × perspectiva (público×privado) — antes de tudo;
        3. alvo contido no escopo declarado.

        ``override`` libera a regra de perspectiva (nº 2) explicitamente; nunca
        libera autorização nem pertencimento ao escopo.
        """
        persp = perspective or self.perspective

        if not self.authorized:
            raise ScopeViolation(
                "Escopo não autorizado: defina 'authorized: true' no scope.yaml "
                "apenas se você tem permissão explícita para testar estes alvos."
            )

        ok, reason = target_allowed(persp, target, override=override)
        if not ok:
            raise PerspectiveViolation(f"Bloqueado por regra de perspectiva: {reason}")

        if not self.contains(target):
            raise ScopeViolation(
                f"Alvo fora do escopo autorizado: {target!r}. "
                "Adicione-o a 'hosts' no scope.yaml (com autorização real)."
            )
