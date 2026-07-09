"""Runner do nuclei — scanner de vulnerabilidades por templates."""

from __future__ import annotations

from vulnforge.engine.base import BaseToolPlugin, ToolResult
from vulnforge.findings.schema import Finding

from .parser import parse


class NucleiRunner(BaseToolPlugin):
    binary = "nuclei"
    name = "nuclei"

    def build_args(
        self,
        target: str,
        *,
        severity: str | None = None,
        templates: str | None = None,
        rate_limit: int = 150,
        **_,
    ) -> list[str]:
        args = ["-u", target, "-jsonl", "-silent", "-rate-limit", str(int(rate_limit))]
        if severity:
            args += ["-severity", severity]
        if templates:
            args += ["-t", templates]
        return args

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
