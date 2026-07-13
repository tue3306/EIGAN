"""Parser do gowitness: JSONL de captura → finding de screenshot (evidência visual).

Um por URL: registra que a página foi capturada (título, status, arquivo). INFO —
é evidência de recon, não uma vulnerabilidade. Só o que a ferramenta reportou (§3.1).
"""

from __future__ import annotations

import json

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "gowitness"


def parse(result: ToolResult, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = str(obj.get("url") or obj.get("final_url") or target)
        title = str(obj.get("title") or "")
        code = obj.get("response_code") or obj.get("status_code")
        shot = str(obj.get("filename") or obj.get("file_name") or "")
        findings.append(
            Finding(
                title=f"Screenshot capturado: {url}" + (f" — {title}" if title else "")[:180],
                severity=Severity.INFO,
                affected_asset=url,
                source_tool=TOOL,
                description=(
                    "Página web capturada (gowitness)"
                    + (f", título '{title}'" if title else "")
                    + (f", HTTP {code}" if code is not None else "")
                    + (f". Arquivo: {shot}" if shot else ".")
                ),
                evidence=shot or line[:200],
                confidence=Confidence.FIRM,
                attack_technique="T1592.002",  # Gather Victim Host Information: Software
                references=["https://attack.mitre.org/techniques/T1592/002/"],
            )
        )
    return findings
