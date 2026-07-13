"""Runner do katana (ProjectDiscovery) — crawler que mapeia a superfície web.

Roda após o httpx confirmar um serviço web vivo (cascata). Saída simples (uma URL
por linha), normalizada pelo ``parser.py`` em um finding que destaca as URLs com
parâmetros — a superfície de injeção que alimenta o scan de vulnerabilidades.
Impacto ``active_safe``: navega links, não explora.
"""

from __future__ import annotations

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


class KatanaRunner(BaseToolPlugin):
    binary = "katana"
    name = "katana"

    def build_args(self, target: str, *, depth: int = 2, rate_limit: int = 150, **_) -> list[str]:
        d = depth if isinstance(depth, int) and 1 <= depth <= 5 else 2
        return [
            "-u",
            target,
            "-silent",
            "-no-color",
            "-depth",
            str(d),
            "-rate-limit",
            str(int(rate_limit)),
        ]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
