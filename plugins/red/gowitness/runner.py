"""Runner do gowitness — screenshot de página web (Chromium headless).

Captura a imagem em ``eigan-screenshots/`` e emite os metadados em JSONL no stdout
(``--write-jsonl -``), normalizados pelo parser. Requer Chromium/Chrome no host.
"""

from __future__ import annotations

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse

_SHOT_DIR = "eigan-screenshots"


class GowitnessRunner(BaseToolPlugin):
    binary = "gowitness"
    name = "gowitness"
    default_timeout = 90

    def build_args(self, target: str, **_) -> list[str]:
        return [
            "scan",
            "single",
            "-u",
            target,
            "--screenshot-path",
            _SHOT_DIR,
            "--write-jsonl",
            "-",
            "--timeout",
            "20",
        ]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
