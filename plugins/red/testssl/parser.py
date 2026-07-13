"""Parser do testssl.sh: JSON de findings TLS → findings normalizados.

testssl (--jsonfile-pretty) emite uma lista de itens ``{id, ip, port, severity,
finding, cve?}``. A ``severity`` é do PRÓPRIO testssl (fonte da ferramenta, não
inventada): mapeamos para o nosso enum e descartamos ruído (OK/INFO/DEBUG). CVEs
citados pela ferramenta entram como referência, sem fabricar score (§3.1).
"""

from __future__ import annotations

import json

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "testssl"

# severidade do testssl → nosso enum. OK/INFO/DEBUG são descartados (não são achados).
_SEV = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "WARN": Severity.LOW,
}


def _items(raw: str) -> list[dict]:
    raw = raw.strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):  # algumas versões embrulham em {"scanResult":[...]}
        for key in ("scanResult", "findings", "results"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = [data]
    return [i for i in data if isinstance(i, dict)]


def parse(result: ToolResult, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for item in _items(result.stdout):
        sev = _SEV.get(str(item.get("severity", "")).upper())
        if sev is None:
            continue  # OK/INFO/DEBUG → não é achado
        fid = str(item.get("id") or "tls")
        text = str(item.get("finding") or "").strip()
        port = str(item.get("port") or "")
        asset = (
            f"{target}:{port}" if port and ":" not in str(target).split("//")[-1] else str(target)
        )
        cve = str(item.get("cve") or "").strip()
        refs = ["https://testssl.sh/"]
        if cve:
            refs = [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cve.split()[:3]] + refs
        findings.append(
            Finding(
                title=f"TLS/{fid}: {text}"[:180],
                severity=sev,
                affected_asset=asset,
                source_tool=TOOL,
                description=f"testssl.sh reportou '{fid}': {text}"
                + (f" (CVE citado: {cve})" if cve else ""),
                evidence=json.dumps(item, ensure_ascii=False)[:500],
                confidence=Confidence.FIRM,
                attack_technique="T1040",  # Network Sniffing (TLS fraco → interceptação)
                references=refs,
            )
        )
    return findings
