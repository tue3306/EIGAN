"""Parser do dnsx: hosts que resolvem viram findings de recon (assets vivos)."""

from __future__ import annotations

import json

from vulnforge.engine.base import ToolResult
from vulnforge.findings.schema import Confidence, Finding, Severity

TOOL = "dnsx"


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
        host = obj.get("host", target)
        a_records = obj.get("a") or []
        status = obj.get("status_code", "")
        # host "vivo" = resolveu (NOERROR) com pelo menos um registro A.
        if status and status != "NOERROR" and not a_records:
            continue
        findings.append(
            Finding(
                title=f"Host DNS ativo: {host}",
                severity=Severity.INFO,
                affected_asset=host,
                source_tool=TOOL,
                description=f"{host} resolveu para {', '.join(a_records) or 'registro DNS'}.",
                evidence=line[:500],
                confidence=Confidence.FIRM,
            )
        )
    return findings
