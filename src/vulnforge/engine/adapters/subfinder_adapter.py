"""Adapter para subfinder (ProjectDiscovery) — enumeração passiva de subdomínio.

APENAS EXTERNAL: dentro da rede (INTERNAL) você já está no perímetro; OSINT de
subdomínio não se aplica. Essa restrição é declarada em
``supported_perspectives`` e o orquestrador respeita — nada de ``if`` no fluxo.
Substitui Assetfinder (redundância). Flags confirmados via ``subfinder -h``.

Recon: alimenta o inventário de assets (não gera Finding de vulnerabilidade).
"""

from __future__ import annotations

import json

from ...findings.schema import Confidence, Finding, Severity
from ...perspective import Perspective
from ..base import BaseToolAdapter, ToolResult


class SubfinderAdapter(BaseToolAdapter):
    binary = "subfinder"
    name = "subfinder"
    supported_perspectives = (Perspective.EXTERNAL,)   # só faz sentido de fora
    version_source = "subfinder -version  # VERIFICAR"
    license = "VERIFICAR"          # MIT (projectdiscovery) — confirmar
    commercial_use = "verify"

    def build_args(self, target: str, **_) -> list[str]:
        return ["-d", target, "-oJ", "-silent"]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # subfinder -oJ: uma linha JSON por subdomínio ({"host": "..."}).
            try:
                host = json.loads(line).get("host", "")
            except json.JSONDecodeError:
                host = line  # tolera saída em texto puro
            host = host.strip()
            if not host or host in seen:
                continue
            seen.add(host)
            findings.append(
                Finding(
                    title=f"Subdomínio descoberto: {host}",
                    severity=Severity.INFO,
                    affected_asset=host,
                    source_tool=self.name,
                    description=f"Subdomínio de {target} descoberto por OSINT passivo.",
                    evidence=line[:500],
                    confidence=Confidence.FIRM,
                    attack_technique="T1590",  # Gather Victim Network Information
                    references=["https://attack.mitre.org/techniques/T1590/"],
                )
            )
        return findings
