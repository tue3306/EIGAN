"""Runner do wpscan — scanner dedicado de WordPress.

Enumera versão/plugins/temas/usuários e vulnerabilidades conhecidas. Saída JSON
para stdout. Um token opcional (env ``WPSCAN_API_TOKEN``) habilita o feed de
vulnerabilidades da WPScan; sem ele, ainda enumera (fingerprint/usuários).
Disparado após WordPress ser detectado (cascata do whatweb).
"""

from __future__ import annotations

import os

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


class WpscanRunner(BaseToolPlugin):
    binary = "wpscan"
    name = "wpscan"
    default_timeout = 240

    def build_args(self, target: str, **_) -> list[str]:
        args = [
            "--url",
            target,
            "--format",
            "json",
            "--no-banner",
            "--random-user-agent",
            "--disable-tls-checks",
        ]
        token = os.getenv("WPSCAN_API_TOKEN")
        if token:
            args += ["--api-token", token]
        return args

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
