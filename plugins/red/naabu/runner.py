"""Runner do naabu — descoberta rápida de portas."""

from __future__ import annotations

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


class NaabuRunner(BaseToolPlugin):
    binary = "naabu"
    name = "naabu"

    def build_args(
        self,
        target: str,
        *,
        ports: str | None = None,
        port_rate: int = 1000,
        rate_limit: int | None = None,
        all_ports: bool = False,
        **_,
    ) -> list[str]:
        # port_rate é o rate de PORTAS (pacotes/s); distinto do rate_limit web.
        # Aceita rate_limit como fallback para compatibilidade.
        rate = int(port_rate if port_rate else (rate_limit or 1000))
        args = ["-host", target, "-json", "-silent", "-rate", str(rate)]
        if all_ports:
            args += ["-p", "-"]  # todas as 65535 portas (máximo esforço)
        elif ports:
            args += ["-p", ports]
        return args

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
