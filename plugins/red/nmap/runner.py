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
        self,
        target: str,
        *,
        ports: str | None = None,
        scripts: bool = False,
        timing: int = 4,
        stealth: bool = False,
        all_ports: bool = False,
        **_,
    ) -> list[str]:
        args = ["-sV", "-oX", "-", "-Pn"]
        # Timing template (-T0 paranoid … -T5 insane). Furtivo baixa para -T2.
        t = 2 if stealth else timing
        if isinstance(t, int) and 0 <= t <= 5:
            args.append(f"-T{t}")
        if _is_root():
            # OS detection precisa de raw sockets (root). Sem root o nmap avisa e
            # segue; ligamos só quando é útil de fato, aproveitando o sudo.
            args.append("-O")
            if stealth:
                # Evasão real (fragmenta pacotes) só com raw sockets — root.
                args += ["-f", "--scan-delay", "200ms"]
        elif stealth:
            # Sem root: evasão possível sem raw sockets (connect scan mais lento).
            args += ["--scan-delay", "300ms", "--max-rate", "50"]
        if all_ports:
            args += ["-p-"]  # varredura completa (65535) — máximo esforço
        elif ports:
            # `ports` é um token isolado (nunca concatenado em shell).
            args += ["-p", ports]
        if scripts:
            args += ["--script", "default,vuln"]
        args.append(target)
        return args

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
