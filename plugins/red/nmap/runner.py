"""Runner do nmap — descoberta de host/porta + serviço/versão (XML nativo)."""

from __future__ import annotations

from vulnforge.engine.base import BaseToolPlugin, ToolResult
from vulnforge.findings.schema import Finding

from .parser import parse


class NmapRunner(BaseToolPlugin):
    binary = "nmap"
    name = "nmap"

    def build_args(self, target: str, *, ports: str | None = None,
                   scripts: bool = False, **_) -> list[str]:
        args = ["-sV", "-oX", "-", "-Pn"]
        if ports:
            # `ports` é um token isolado (nunca concatenado em shell).
            args += ["-p", ports]
        if scripts:
            args += ["--script", "default,vuln"]
        args.append(target)
        return args

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
