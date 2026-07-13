"""Runner do sqlmap — validação autorizada de injeção SQL (não-destrutivo).

Modo ``--batch`` (não-interativo), sem dump/OS-shell: apenas CONFIRMA o ponto de
injeção, o tipo e o DBMS. Intrusivo (impact_class exploit_validation) — roda só
dentro do escopo autorizado. Precisa de uma URL com parâmetro (vinda do crawl/
descoberta) para ter o que testar.
"""

from __future__ import annotations

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


class SqlmapRunner(BaseToolPlugin):
    binary = "sqlmap"
    name = "sqlmap"
    default_timeout = 240  # sqlmap é mais lento que os scanners de recon

    def build_args(self, target: str, *, level: int = 1, risk: int = 1, **_) -> list[str]:
        lvl = level if isinstance(level, int) and 1 <= level <= 5 else 1
        rsk = risk if isinstance(risk, int) and 1 <= risk <= 3 else 1
        return [
            "-u",
            target,
            "--batch",  # não-interativo (nunca pergunta)
            "--disable-coloring",
            "--level",
            str(lvl),
            "--risk",
            str(rsk),
            "--technique",
            "BEUS",  # boolean/error/union/stacked — sem time-based (mais rápido)
            "--timeout",
            "15",
            "--retries",
            "1",
            "--threads",
            "2",
            # explicitamente NÃO passamos --dump/--os-shell/--file-read: só validação.
        ]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
