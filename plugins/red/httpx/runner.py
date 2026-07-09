"""Runner do httpx (ProjectDiscovery) — probe web + tech-detect.

Guard de identidade (§5 na prática): existe um binário homônimo — o cliente HTTP
``httpx`` do Python. ``available()`` confirma que o binário no PATH é o da
ProjectDiscovery antes de habilitar; caso contrário, o plugin se declara
indisponível (é pulado, sem emitir dado inventado).
"""

from __future__ import annotations

import shutil
import subprocess

from vulnforge.engine.base import BaseToolPlugin, ToolResult
from vulnforge.findings.schema import Finding

from .parser import parse


class HttpxRunner(BaseToolPlugin):
    binary = "httpx"
    name = "httpx"

    _identity_ok: bool | None = None

    def available(self) -> bool:
        if shutil.which(self.binary) is None:
            return False
        if HttpxRunner._identity_ok is None:
            HttpxRunner._identity_ok = self._is_projectdiscovery()
        return HttpxRunner._identity_ok

    def _is_projectdiscovery(self) -> bool:
        """Confirma que o binário é o httpx da ProjectDiscovery e não o cliente
        HTTP homônimo do Python."""
        try:
            out = subprocess.run(
                [self.binary, "-h"], capture_output=True, text=True,
                timeout=10, shell=False, check=False,
            )
        except (subprocess.SubprocessError, OSError):
            return False
        blob = (out.stdout + out.stderr).lower()
        # marcadores exclusivos do httpx-PD; ausentes no cliente Python.
        return "tech-detect" in blob or "projectdiscovery" in blob or "-td," in blob

    def build_args(self, target: str, *, rate_limit: int = 150, **_) -> list[str]:
        return ["-u", target, "-json", "-silent", "-td", "-title",
                "-status-code", "-rate-limit", str(int(rate_limit))]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
