"""Runner do testssl.sh — avaliação TLS/SSL (saída JSON via arquivo).

Como o nikto, o testssl escreve o JSON estruturado em um ARQUIVO
(``--jsonfile-pretty``); ``scan`` usa um temporário, roda, lê e delega ao parser.
``--fast`` + ``--quiet`` reduzem o tempo (testssl é minucioso e lento).
"""

from __future__ import annotations

import os
import tempfile

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


class TestsslRunner(BaseToolPlugin):
    binary = "testssl.sh"
    name = "testssl"
    default_timeout = 400  # testssl é lento mesmo com --fast

    def build_args(self, target: str, *, outfile: str = "", **_) -> list[str]:
        return [
            "--jsonfile-pretty",
            outfile or "-",
            "--quiet",
            "--warnings",
            "off",
            "--fast",  # não itera cifra a cifra — muito mais rápido
            "--color",
            "0",
            target,
        ]

    def scan(self, target: str, *, timeout: int | None = None, **options) -> list[Finding]:
        fd, path = tempfile.mkstemp(prefix="eigan_testssl_", suffix=".json")
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
