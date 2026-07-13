"""Parser do dalfox: JSONL de achados → findings de XSS.

dalfox emite uma linha JSON por achado. ``type`` = V (verificado/PoC executado),
R (refletido), G (grep): V é o mais forte (HIGH). Sem achado ⇒ nada (§3.1).
"""

from __future__ import annotations

import json

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "dalfox"

_SEV = {"V": Severity.HIGH, "R": Severity.MEDIUM, "G": Severity.LOW}
_CONF = {"V": Confidence.CONFIRMED, "R": Confidence.FIRM, "G": Confidence.TENTATIVE}


def parse(result: ToolResult, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        kind = str(obj.get("type", "")).upper()[:1]
        sev = _SEV.get(kind, Severity.MEDIUM)
        param = str(obj.get("param", "") or "?")
        inject = str(obj.get("inject_type", "") or "")
        poc = str(obj.get("data") or obj.get("poc") or "")
        evidence = str(obj.get("evidence", "") or "")
        findings.append(
            Finding(
                title=f"XSS ({'verificado' if kind == 'V' else 'refletido'}) no parâmetro {param}"[
                    :180
                ],
                severity=sev,
                affected_asset=target,
                source_tool=TOOL,
                cwe="CWE-79",
                owasp="A03:2021",  # Injection (inclui XSS no Top 10 2021)
                description=(
                    f"dalfox reportou XSS ({inject or 'reflected'}) no parâmetro "
                    f"'{param}' de {target}."
                ),
                evidence=(poc or evidence or line)[:600],
                reproduction=poc[:400] if poc else "",
                confidence=_CONF.get(kind, Confidence.FIRM),
                attack_technique="T1059.007",  # Command and Scripting Interpreter: JavaScript
                references=[
                    "https://cwe.mitre.org/data/definitions/79.html",
                    "https://owasp.org/www-community/attacks/xss/",
                ],
            )
        )
    return findings
