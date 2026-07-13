"""Parser do nikto: JSON de vulnerabilidades → findings normalizados.

nikto varia o envelope do JSON entre versões (lista OU objeto, com um bloco
``vulnerabilities``). Extraímos cada item (msg/url/method/id) de forma defensiva.
Severidade heurística NOSSA (não é score externo, §3.1): a maioria é LOW/INFO;
palavras de alto risco sobem para MEDIUM. Nada é inventado.
"""

from __future__ import annotations

import json

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "nikto"

_HIGH_RISK = ("sql", "traversal", "xss", "shell", "rce", "remote file", "lfi", "rfi")
_INFO_HINT = ("header", "x-frame", "content-type", "cookie", "banner")


def _vulns(raw: str) -> list[dict]:
    raw = raw.strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    hosts = data if isinstance(data, list) else [data]
    vulns: list[dict] = []
    for h in hosts:
        if isinstance(h, dict) and isinstance(h.get("vulnerabilities"), list):
            vulns.extend(v for v in h["vulnerabilities"] if isinstance(v, dict))
    return vulns


def _severity(msg: str) -> Severity:
    low = msg.lower()
    if any(k in low for k in _HIGH_RISK):
        return Severity.MEDIUM
    if any(k in low for k in _INFO_HINT):
        return Severity.INFO
    return Severity.LOW


def parse(result: ToolResult, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for v in _vulns(result.stdout):
        msg = str(v.get("msg") or v.get("title") or "").strip()
        if not msg:
            continue
        url = str(v.get("url") or "")
        method = str(v.get("method") or "GET")
        vid = str(v.get("id") or v.get("OSVDB") or "")
        findings.append(
            Finding(
                title=f"nikto: {msg}"[:180],
                severity=_severity(msg),
                affected_asset=f"{target}{url}" if url.startswith("/") else (url or target),
                source_tool=TOOL,
                description=f"nikto reportou: {msg}" + (f" (id {vid})" if vid else ""),
                evidence=f"{method} {url} — {msg}"[:500],
                confidence=Confidence.TENTATIVE,  # nikto tem falsos-positivos conhecidos
                attack_technique="T1595.002",  # Active Scanning: Vulnerability Scanning
                references=["https://attack.mitre.org/techniques/T1595/002/"],
            )
        )
    return findings
