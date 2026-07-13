"""Runner do amass (OWASP) — enumeração de subdomínio abrangente por OSINT passivo.

Modo ``enum -passive`` (sem resolução ativa: mais rápido e furtivo). Extrai o
domínio do alvo (aceita IP/host/URL). Saída: subdomínios (um por linha),
normalizada pelo ``parser.py``. Impacto ``passive`` (só consultas OSINT).
"""

from __future__ import annotations

from urllib.parse import urlparse

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


def _domain(target: str) -> str:
    t = target.strip()
    if "://" in t:
        t = urlparse(t).hostname or t
    # remove porta (host:porta), preservando IPv6 entre colchetes
    if t.count(":") == 1 and "[" not in t:
        t = t.split(":")[0]
    return t


class AmassRunner(BaseToolPlugin):
    binary = "amass"
    name = "amass"
    default_timeout = 300  # amass é minucioso; -timeout abaixo é o teto real

    def build_args(self, target: str, *, timeout_min: int = 2, **_) -> list[str]:
        return [
            "enum",
            "-passive",
            "-d",
            _domain(target),
            "-timeout",
            str(int(timeout_min)),
            "-nocolor",
            "-silent",
        ]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
