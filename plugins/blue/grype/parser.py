"""Parser do grype: matches[].vulnerability → findings de CVE.

Severity da própria ferramenta (fonte §3.1). CVE + artefato + versão como
evidência/referência, sem fabricar score.
"""

from __future__ import annotations

import json

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "grype"

_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "negligible": Severity.INFO,
    "unknown": Severity.INFO,
}


def parse(result: ToolResult, target: str) -> list[Finding]:
    raw = (result.stdout or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    seen: set[str] = set()
    for m in data.get("matches") or []:
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        cve = str(vuln.get("id") or "")
        name = str(art.get("name") or "")
        key = f"{cve}:{name}"
        if not cve or key in seen:
            continue
        seen.add(key)
        fix = vuln.get("fix") or {}
        fixed = ", ".join(fix.get("versions") or [])
        findings.append(
            Finding(
                title=f"{cve} em {name} {art.get('version', '')}".strip()[:180],
                severity=_SEV.get(str(vuln.get("severity", "")).lower(), Severity.INFO),
                affected_asset=f"{target}:{name}" if name else target,
                source_tool=TOOL,
                owasp="A06:2021",
                description=(
                    f"{cve} no pacote {name} {art.get('version', '')}"
                    + (f"; corrigido em {fixed}" if fixed else "; sem correção conhecida")
                ),
                evidence=json.dumps({"id": cve, "pkg": name, "severity": vuln.get("severity")})[
                    :400
                ],
                confidence=Confidence.FIRM,
                attack_technique="T1195.001",
                references=[f"https://nvd.nist.gov/vuln/detail/{cve}"]
                if cve.startswith("CVE-")
                else ["https://github.com/anchore/grype"],
            )
        )
    return findings
