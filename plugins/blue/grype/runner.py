"""Runner do grype — CVEs de imagem/diretório/SBOM (auto-detecta o alvo)."""

from __future__ import annotations

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


class GrypeRunner(BaseToolPlugin):
    binary = "grype"
    name = "grype"
    default_timeout = 300

    def build_args(self, target: str, **_) -> list[str]:
        return [target, "-o", "json", "-q"]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
