"""Runner do enum4linux — enumeração SMB/Samba via null session (seguro)."""

from __future__ import annotations

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


class Enum4linuxRunner(BaseToolPlugin):
    binary = "enum4linux"
    name = "enum4linux"
    default_timeout = 300

    def build_args(self, target: str, **_) -> list[str]:
        # -a: enumeração "all-simple" (usuários, shares, política, OS). Lista de
        # argumentos (nunca string única / shell) — o alvo é um token isolado.
        return ["-a", target]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
