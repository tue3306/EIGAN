"""Runner do subfinder — enumeração passiva de subdomínio (só EXTERNAL)."""

from __future__ import annotations

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


class SubfinderRunner(BaseToolPlugin):
    binary = "subfinder"
    name = "subfinder"

    def build_args(self, target: str, **_) -> list[str]:
        return ["-d", target, "-oJ", "-silent"]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
