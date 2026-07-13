"""Runner do dalfox — validação de XSS (refletido/DOM) por injeção de payload.

Modo ``url`` com saída JSONL (uma linha por achado). Intrusivo — envia payloads
de XSS; roda só dentro do escopo autorizado. Ideal com uma URL que tenha
parâmetros (vinda do crawl/descoberta de conteúdo).
"""

from __future__ import annotations

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


class DalfoxRunner(BaseToolPlugin):
    binary = "dalfox"
    name = "dalfox"
    default_timeout = 180

    def build_args(self, target: str, **_) -> list[str]:
        return [
            "url",
            target,
            "--format",
            "jsonl",
            "--silence",
            "--no-color",
            "--no-spinner",
            "--skip-bav",  # pula o "basic-another-vuln" (foco em XSS, mais rápido)
            "--worker",
            "20",
            "--timeout",
            "10",
        ]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
