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
from urllib.parse import urlparse

import yaml


class ScopeViolation(Exception):
    """Lançada quando um alvo fora do escopo autorizado é submetido."""


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

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        data = yaml.safe_load(Path(path).read_text()) or {}
        return cls(
            authorized=bool(data.get("authorized", False)),
            engagement=str(data.get("engagement", "")),
            hosts=[str(h) for h in data.get("hosts", [])],
            exclude=[str(h) for h in data.get("exclude", [])],
        )

    @staticmethod
    def _target_host(target: str) -> str:
        """Extrai o host de um alvo que pode ser IP, hostname ou URL."""
        if "://" in target:
            return urlparse(target).hostname or target
        # remove porta de "host:port" (sem esquema)
        if target.count(":") == 1 and "]" not in target:
            return target.split(":")[0]
        return target

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

    def enforce(self, target: str) -> None:
        """Bloqueia por padrão. Levanta :class:`ScopeViolation` se o escopo não
        estiver autorizado ou o alvo não estiver contido nele."""
        if not self.authorized:
            raise ScopeViolation(
                "Escopo não autorizado: defina 'authorized: true' no scope.yaml "
                "apenas se você tem permissão explícita para testar estes alvos."
            )
        if not self.contains(target):
            raise ScopeViolation(
                f"Alvo fora do escopo autorizado: {target!r}. "
                "Adicione-o a 'hosts' no scope.yaml (com autorização real)."
            )
