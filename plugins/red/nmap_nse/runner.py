"""Runner do nmap-nse — 2ª onda do nmap com a Scripting Engine (NSE).

Reusa o binário nmap com flags diferentes (``--script``) — é o "voltar ao nmap
e fazer outro escaneamento". Lista de argumentos (nunca shell). O conjunto de
scripts é fixo e seguro-por-construção; ``scripts`` opcional permite refinar por
serviço quando o chamador souber (ex.: ``smb-vuln-*``)."""

from __future__ import annotations

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse

_DEFAULT_SCRIPTS = "default,vuln"


class NmapNseRunner(BaseToolPlugin):
    binary = "nmap"
    name = "nmap-nse"
    default_timeout = 900

    def build_args(
        self, target: str, *, ports: str | None = None, scripts: str | None = None, **_
    ) -> list[str]:
        args = ["-sV", "-Pn", "-oX", "-", "--script", scripts or _DEFAULT_SCRIPTS]
        if ports:
            args += ["-p", ports]  # token isolado, nunca concatenado
        args.append(target)
        return args

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
