"""Parser do trivy: JSON (Results[].Vulnerabilities[]) → findings de CVE.

Usa a Severity da PRÓPRIA ferramenta (fonte, não inventada §3.1). CVE + pacote +
versão instalada/corrigida entram como evidência/referência sem fabricar score.
"""

from __future__ import annotations

import json

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "trivy"

_SEV = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
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
    for res in data.get("Results") or []:
        where = str(res.get("Target") or target)
        for v in res.get("Vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            cve = str(v.get("VulnerabilityID") or "")
            pkg = str(v.get("PkgName") or "")
            key = f"{cve}:{pkg}:{where}"
            if not cve or key in seen:
                continue
            seen.add(key)
            fixed = str(v.get("FixedVersion") or "")
            findings.append(
                Finding(
                    title=f"{cve} em {pkg} {v.get('InstalledVersion', '')}".strip()[:180],
                    severity=_SEV.get(str(v.get("Severity", "")).upper(), Severity.INFO),
                    affected_asset=f"{where}:{pkg}" if pkg else where,
                    source_tool=TOOL,
                    owasp="A06:2021",  # Vulnerable and Outdated Components
                    description=(
                        f"{v.get('Title') or cve} — pacote {pkg} "
                        f"{v.get('InstalledVersion', '')}"
                        + (f"; corrigido em {fixed}" if fixed else "; sem correção disponível")
                    ),
                    evidence=json.dumps(
                        {k: v.get(k) for k in ("VulnerabilityID", "PkgName", "Severity")},
                        ensure_ascii=False,
                    )[:400],
                    confidence=Confidence.FIRM,
                    attack_technique="T1195.001",  # Supply Chain Compromise: Dependencies
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve}"]
                    if cve.startswith("CVE-")
                    else ["https://github.com/aquasecurity/trivy"],
                )
            )
    return findings
