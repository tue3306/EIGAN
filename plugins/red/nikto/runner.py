"""Runner do nikto — scanner de servidor web (saída JSON via arquivo).

O nikto escreve o resultado em um ARQUIVO (não stdout), então ``scan`` usa um
arquivo temporário: monta os args com o caminho, roda, lê o JSON e delega ao
parser. ``-maxtime`` limita o tempo (o nikto pode demorar). Intrusivo — só dentro
do escopo autorizado.
"""

from __future__ import annotations

import os
import tempfile

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


class NiktoRunner(BaseToolPlugin):
    binary = "nikto"
    name = "nikto"
    default_timeout = 400  # nikto é lento; o -maxtime abaixo é o teto real por alvo

    def build_args(self, target: str, *, outfile: str = "", maxtime: int = 180, **_) -> list[str]:
        return [
            "-h",
            target,
            "-Format",
            "json",
            "-output",
            outfile or "-",
            "-maxtime",
            f"{int(maxtime)}s",
            "-ask",
            "no",
            "-nointeractive",
        ]

    def scan(self, target: str, *, timeout: int | None = None, **options) -> list[Finding]:
        fd, path = tempfile.mkstemp(prefix="eigan_nikto_", suffix=".json")
        os.close(fd)
        try:
            args = self.build_args(target, outfile=path, **options)
            result = self._run(args, timeout=timeout)
            data = ""
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    data = fh.read()
            except OSError:
                data = ""
            merged = ToolResult(
                result.exit_code, data or result.stdout, result.stderr, result.timed_out
            )
            return self.parse(merged, target)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
