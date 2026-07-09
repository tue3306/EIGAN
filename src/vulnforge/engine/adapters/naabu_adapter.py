"""Adapter para naabu (ProjectDiscovery) — descoberta rápida de portas.

Substitui RustScan no arsenal podado (redundância). Roda antes do nmap, que
faz service/version nas portas que o naabu abrir. Flags confirmados via
``naabu -h`` (fonte oficial = a própria ferramenta). Saída JSONL documentada.
"""

from __future__ import annotations

import json

from ...findings.schema import Confidence, Finding, Severity
from ...perspective import Perspective
from ..base import BaseToolAdapter, ToolResult


class NaabuAdapter(BaseToolAdapter):
    binary = "naabu"
    name = "naabu"
    supported_perspectives = (Perspective.EXTERNAL, Perspective.INTERNAL)
    version_source = "naabu -version  # VERIFICAR"
    license = "VERIFICAR"          # MIT (projectdiscovery) — confirmar
    commercial_use = "verify"

    def build_args(self, target: str, *, ports: str | None = None,
                   rate_limit: int = 1000, **_) -> list[str]:
        args = ["-host", target, "-json", "-silent", "-rate", str(int(rate_limit))]
        if ports:
            args += ["-p", ports]
        return args

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
            ip = obj.get("ip") or obj.get("host") or target
            port = obj.get("port")
            if port is None:
                continue
            proto = obj.get("protocol", "tcp")
            findings.append(
                Finding(
                    title=f"Porta aberta {port}/{proto}",
                    severity=Severity.INFO,
                    affected_asset=f"{ip}:{port}",
                    source_tool=self.name,
                    description=f"naabu detectou {ip}:{port}/{proto} aberta.",
                    evidence=line[:500],
                    confidence=Confidence.FIRM,
                    attack_technique="T1046",  # Network Service Discovery
                    references=["https://attack.mitre.org/techniques/T1046/"],
                )
            )
        return findings
