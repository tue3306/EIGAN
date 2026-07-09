"""Adapter para httpx (ProjectDiscovery) — probe web + tech-detect.

ATENÇÃO (regra §5 aplicada na prática): existe um binário homônimo — o cliente
HTTP ``httpx`` do Python (biblioteca Encode). Rodar os flags do httpx-PD contra
ele produziria lixo. Por isso ``available()`` faz um *guard de identidade*:
confirma que o ``httpx`` no PATH é o da ProjectDiscovery antes de habilitar o
adapter. Se for o cliente Python, o adapter se declara indisponível (é pulado,
sem emitir dado inventado).

Substitui httprobe (redundância). Recon: alimenta o inventário de assets.
"""

from __future__ import annotations

import json
import shutil
import subprocess

from ...findings.schema import Confidence, Finding, Severity
from ...perspective import Perspective
from ..base import BaseToolAdapter, ToolResult


class HttpxAdapter(BaseToolAdapter):
    binary = "httpx"
    name = "httpx"
    supported_perspectives = (Perspective.EXTERNAL, Perspective.INTERNAL)
    version_source = "httpx -version  # VERIFICAR (ProjectDiscovery, não o cliente Python)"
    license = "VERIFICAR"          # MIT (projectdiscovery) — confirmar
    commercial_use = "verify"

    _identity_ok: bool | None = None

    def available(self) -> bool:
        if shutil.which(self.binary) is None:
            return False
        if HttpxAdapter._identity_ok is None:
            HttpxAdapter._identity_ok = self._is_projectdiscovery()
        return HttpxAdapter._identity_ok

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
        findings: list[Finding] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url") or obj.get("input") or target
            status = obj.get("status_code") or obj.get("status-code")
            tech = obj.get("tech") or obj.get("technologies") or []
            title = obj.get("title", "")
            server = obj.get("webserver", "")
            desc = f"Serviço web vivo em {url} (status {status})."
            if tech:
                desc += f" Tecnologias: {', '.join(tech)}."
            findings.append(
                Finding(
                    title=f"Web vivo: {url}",
                    severity=Severity.INFO,
                    affected_asset=url,
                    source_tool=self.name,
                    description=desc,
                    evidence=json.dumps({"title": title, "server": server, "tech": tech})[:500],
                    confidence=Confidence.FIRM,
                )
            )
        return findings
