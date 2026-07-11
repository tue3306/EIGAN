"""Parser do subfinder: normaliza subdomínios descobertos em findings de recon."""

from __future__ import annotations

import json

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "subfinder"


def parse(result: ToolResult, target: str) -> list[Finding]:
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
                source_tool=TOOL,
                description=f"Subdomínio de {target} descoberto por OSINT passivo.",
                evidence=line[:500],
                confidence=Confidence.FIRM,
                attack_technique="T1590",  # Gather Victim Network Information
                references=["https://attack.mitre.org/techniques/T1590/"],
            )
        )
    return findings
