"""Parser do amass: subdomínios (um por linha) → findings de recon.

amass ``-silent`` imprime um nome por linha. Filtra ruído (linhas sem ponto ou com
espaço) e deduplica. Só o que a ferramenta descobriu — nada inventado (§3.1).
"""

from __future__ import annotations

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "amass"


def parse(result: ToolResult, target: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for line in result.stdout.splitlines():
        host = line.strip().lower()
        # um subdomínio válido: sem espaço, com ponto, sem caractere de log/seta.
        if not host or " " in host or "." not in host or any(c in host for c in "→:/[]"):
            continue
        if host in seen:
            continue
        seen.add(host)
        findings.append(
            Finding(
                title=f"Subdomínio descoberto: {host}",
                severity=Severity.INFO,
                affected_asset=host,
                source_tool=TOOL,
                description=f"Subdomínio de {target} descoberto por OSINT passivo (amass).",
                evidence=host[:200],
                confidence=Confidence.FIRM,
                attack_technique="T1590.002",  # Gather Victim Network Information: DNS
                references=["https://attack.mitre.org/techniques/T1590/002/"],
            )
        )
    return findings
