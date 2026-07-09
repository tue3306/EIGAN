"""Adapter para nuclei — scanner de vulnerabilidades por templates.

Peça central do engine (como no Strix). Faz o parse do JSONL (``-jsonl``),
formato documentado (https://docs.projectdiscovery.io/tools/nuclei/), mapeando
a severidade do nuclei e o CVSS/CVE quando presentes no template. IDs de CVE
vindos do template são tratados como evidência, não como fato enriquecido — o
enriquecimento real contra NVD/OSV é responsabilidade de outra camada.
"""

from __future__ import annotations

import json

from ...findings.schema import CVSS, Confidence, Finding, Severity
from ..base import BaseToolAdapter, ToolResult

_SEV_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFO,
}


class NucleiAdapter(BaseToolAdapter):
    binary = "nuclei"
    name = "nuclei"

    def build_args(self, target: str, *, severity: str | None = None,
                   templates: str | None = None, rate_limit: int = 150, **_) -> list[str]:
        args = ["-u", target, "-jsonl", "-silent", "-rate-limit", str(int(rate_limit))]
        if severity:
            args += ["-severity", severity]
        if templates:
            args += ["-t", templates]
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

            info = obj.get("info", {})
            sev = _SEV_MAP.get(str(info.get("severity", "info")).lower(), Severity.INFO)
            classification = info.get("classification", {}) or {}

            cvss = None
            score = classification.get("cvss-score")
            if isinstance(score, (int, float)):
                # a versão vem do vetor quando disponível; senão marcamos UNVERIFIED
                vector = classification.get("cvss-metrics", "") or ""
                version = "3.1" if vector.startswith("CVSS:3.1") else (
                    "4.0" if vector.startswith("CVSS:4.0") else "unknown"
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
                    source_tool=self.name,
                    cvss=cvss,
                    cwe=cwe,
                    description=info.get("description", "") or "",
                    evidence=(obj.get("extracted-results") and json.dumps(obj["extracted-results"]))
                    or obj.get("matcher-name", "") or line[:2000],
                    reproduction=f"nuclei -u {target} -t {obj.get('template-id','')}",
                    references=refs,
                    # CVE do template não foi confirmado contra NVD nesta camada:
                    confidence=Confidence.UNVERIFIED if cve_ids else Confidence.FIRM,
                )
            )
        return findings
