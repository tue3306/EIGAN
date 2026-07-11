"""Runner do naabu — descoberta rápida de portas."""

from __future__ import annotations

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


class NaabuRunner(BaseToolPlugin):
    binary = "naabu"
    name = "naabu"

    def build_args(
        self, target: str, *, ports: str | None = None, rate_limit: int = 1000, **_
    ) -> list[str]:
        args = ["-host", target, "-json", "-silent", "-rate", str(int(rate_limit))]
        if ports:
            args += ["-p", ports]
        return args

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
