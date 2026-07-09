"""Runner do dnsx — resolução DNS. O host chega via stdin (target_via_stdin)."""

from __future__ import annotations

from vulnforge.engine.base import BaseToolPlugin, ToolResult
from vulnforge.findings.schema import Finding

from .parser import parse


class DnsxRunner(BaseToolPlugin):
    binary = "dnsx"
    name = "dnsx"
    target_via_stdin = True        # recebe o host pela entrada padrão

    def build_args(self, target: str, **_) -> list[str]:
        # host chega via stdin; -a resolve registros A, -resp inclui a resposta.
        return ["-json", "-silent", "-a", "-resp"]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
