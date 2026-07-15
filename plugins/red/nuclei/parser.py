"""Parser do nuclei: JSONL (-jsonl) → findings normalizados.

Mapeia severidade, CVSS e CWE quando presentes no template. CVE vindo do template
é tratado como EVIDÊNCIA e marca o finding como ``UNVERIFIED`` (confirmação real
contra NVD/OSV é do Risk Engine, não desta camada).
"""

from __future__ import annotations

import json

from eigan.engine.base import ToolResult
from eigan.findings.schema import CVSS, Confidence, Finding, Severity

TOOL = "nuclei"

_SEV_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFO,
}


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

        info = obj.get("info", {})
        sev = _SEV_MAP.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        classification = info.get("classification", {}) or {}

        cvss = None
        score = classification.get("cvss-score")
        # CVSS válido é 0–10 (schema Field ge=0/le=10). Um template custom/quebrado
        # pode emitir score fora da faixa; ignoramos o CVSS inválido (sem fabricar
        # nem clampar, §2) em vez de deixar 1 template ruim derrubar o parse inteiro
        # e descartar TODAS as findings do nuclei (§24).
        if isinstance(score, (int, float)) and 0.0 <= score <= 10.0:
            vector = classification.get("cvss-metrics", "") or ""
            version = (
                "3.1"
                if vector.startswith("CVSS:3.1")
                else ("4.0" if vector.startswith("CVSS:4.0") else "unknown")
            )
            cvss = CVSS(version=version, score=float(score), vector=vector or None)

        cwe_ids = classification.get("cwe-id") or []
        cwe = cwe_ids[0].upper() if cwe_ids else None
        cve_ids = classification.get("cve-id") or []

        refs = list(info.get("reference") or [])
        for cve in cve_ids:
            refs.append(f"https://nvd.nist.gov/vuln/detail/{cve}")

        findings.append(
            Finding(
                title=info.get("name", obj.get("template-id", "nuclei finding")),
                severity=sev,
                affected_asset=obj.get("matched-at", target),
                source_tool=TOOL,
                cvss=cvss,
                cwe=cwe,
                description=info.get("description", "") or "",
                evidence=(obj.get("extracted-results") and json.dumps(obj["extracted-results"]))
                or obj.get("matcher-name", "")
                or line[:2000],
                reproduction=f"nuclei -u {target} -t {obj.get('template-id', '')}",
                references=refs,
                # CVE do template não confirmado contra NVD nesta camada:
                confidence=Confidence.UNVERIFIED if cve_ids else Confidence.FIRM,
            )
        )
    return findings
