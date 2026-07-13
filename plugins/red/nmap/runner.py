"""Runner do nmap — descoberta de host/porta + serviço/versão (XML nativo).

Privilégio (sudo): o nmap **funciona sem root** — cai automaticamente para o TCP
connect scan (``-sT``). COM root ele usa SYN scan (mais rápido/discreto) e habilita
a **detecção de SO** (``-O``), que exige raw sockets. O runner detecta o privilégio
e liga o ``-O`` só quando é root — assim ``sudo`` de fato entrega mais, sem quebrar
o modo sem privilégio. Ver a seção de privilégios no README.
"""

from __future__ import annotations

import os

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


def _is_root() -> bool:
    """True se o processo tem privilégio (POSIX). Fora de POSIX, assume não-root."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


class NmapRunner(BaseToolPlugin):
    binary = "nmap"
    name = "nmap"

    def build_args(
        self, target: str, *, ports: str | None = None, scripts: bool = False, **_
    ) -> list[str]:
        args = ["-sV", "-oX", "-", "-Pn"]
        if _is_root():
            # OS detection precisa de raw sockets (root). Sem root o nmap avisa e
            # segue; ligamos só quando é útil de fato, aproveitando o sudo.
            args.append("-O")
        if ports:
            # `ports` é um token isolado (nunca concatenado em shell).
            args += ["-p", ports]
        if scripts:
            args += ["--script", "default,vuln"]
        args.append(target)
        return args

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
