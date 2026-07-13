"""Parser do sqlmap: stdout → finding de injeção SQL confirmada.

sqlmap não emite JSON estável no stdout; extraímos os marcadores canônicos que ele
imprime ao confirmar uma injeção ("injection point(s)", "Parameter:", "Type:",
"back-end DBMS"). Sem injeção confirmada ⇒ nenhum finding (não inventamos §3.1).
"""

from __future__ import annotations

import re

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "sqlmap"

_PARAM = re.compile(r"Parameter:\s*(.+)")
_TYPE = re.compile(r"Type:\s*(.+)")
_DBMS = re.compile(r"back-end DBMS:\s*(.+)")
_CONFIRMED = "the following injection point"


def parse(result: ToolResult, target: str) -> list[Finding]:
    out = result.stdout or ""
    if _CONFIRMED not in out.lower():
        return []  # nenhuma injeção confirmada

    param_m = _PARAM.search(out)
    types = [m.group(1).strip() for m in _TYPE.finditer(out)]
    dbms_m = _DBMS.search(out)
    param = param_m.group(1).strip() if param_m else "?"
    dbms = dbms_m.group(1).strip() if dbms_m else "desconhecido"

    # Recorta o bloco de evidência do relatório do sqlmap.
    idx = out.lower().find(_CONFIRMED)
    evidence = out[idx : idx + 700].strip()

    return [
        Finding(
            title=f"Injeção SQL confirmada no parâmetro {param}",
            severity=Severity.CRITICAL,
            affected_asset=target,
            source_tool=TOOL,
            cwe="CWE-89",
            owasp="A03:2021",  # Injection
            description=(
                f"sqlmap confirmou injeção SQL em {target} (parâmetro {param}; "
                f"tipos: {', '.join(types) or 'n/d'}; DBMS: {dbms}). "
                "Validação não-destrutiva (sem dump)."
            ),
            evidence=evidence,
            reproduction=f"sqlmap -u {target} --batch",
            confidence=Confidence.CONFIRMED,
            attack_technique="T1190",  # Exploit Public-Facing Application
            references=[
                "https://cwe.mitre.org/data/definitions/89.html",
                "https://owasp.org/Top10/A03_2021-Injection/",
            ],
        )
    ]
