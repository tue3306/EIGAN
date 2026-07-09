"""Parser do naabu: portas abertas (JSONL) → findings informativos."""

from __future__ import annotations

import json

from vulnforge.engine.base import ToolResult
from vulnforge.findings.schema import Confidence, Finding, Severity

TOOL = "naabu"


def parse(result: ToolResult, target: str) -> list[Finding]:
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
                source_tool=TOOL,
                description=f"naabu detectou {ip}:{port}/{proto} aberta.",
                evidence=line[:500],
                confidence=Confidence.FIRM,
                attack_technique="T1046",  # Network Service Discovery
                references=["https://attack.mitre.org/techniques/T1046/"],
            )
        )
    return findings
