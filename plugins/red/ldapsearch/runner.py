"""Runner do ldapsearch — enumeração LDAP/AD por bind anônimo (RootDSE).

Consulta o RootDSE (naming contexts, versão, domínio) com bind ANÔNIMO (``-x``,
sem credencial) — assumed breach / rede interna. Se o servidor responde, já é um
achado (exposição de informação de diretório). Disparado quando o nmap acha LDAP
(389/636/3268).
"""

from __future__ import annotations

from urllib.parse import urlparse

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


def _host(target: str) -> str:
    t = target.strip()
    if "://" in t:
        t = urlparse(t).hostname or t
    if t.count(":") == 1 and "[" not in t:
        t = t.split(":")[0]
    return t


class LdapsearchRunner(BaseToolPlugin):
    binary = "ldapsearch"
    name = "ldapsearch"
    default_timeout = 60

    def build_args(self, target: str, **_) -> list[str]:
        return [
            "-x",  # bind simples anônimo (sem SASL/credencial)
            "-o",
            "nettimeout=15",
            "-H",
            f"ldap://{_host(target)}",
            "-s",
            "base",  # só o RootDSE (não varre a árvore inteira)
            "-b",
            "",
            "*",
            "+",  # atributos de usuário + operacionais (namingContexts etc.)
        ]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
