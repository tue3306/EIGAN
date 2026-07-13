"""Runner do trivy — CVEs de imagem/filesystem/repo.

Detecta o modo pelo alvo: caminho existente → ``fs``; senão → ``image``. Saída JSON
normalizada pelo parser. Impacto passivo (analisa artefato, não a rede).
"""

from __future__ import annotations

import os

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


class TrivyRunner(BaseToolPlugin):
    binary = "trivy"
    name = "trivy"
    default_timeout = 300

    def build_args(self, target: str, **_) -> list[str]:
        mode = "fs" if os.path.exists(target) else "image"
        return [mode, target, "--format", "json", "--quiet", "--scanners", "vuln"]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
