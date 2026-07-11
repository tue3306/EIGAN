"""Parser do enum4linux: saída textual → findings de SMB/Samba normalizados.

enum4linux imprime texto (não JSON): usuários (``user:[nome]``), shares
(``//host/SHARE ... Mapping: OK``), domínio/OS e política de senha. Parseamos os
marcadores documentados de forma tolerante. Nenhum CVE é afirmado aqui (§3.1):
severidade vem de heurística de exposição NOSSA, não de score externo.
"""

from __future__ import annotations

import re

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "enum4linux"

_USER = re.compile(r"user:\[([^\]]+)\]", re.IGNORECASE)
_SHARE_OK = re.compile(r"//(\S+?)/(\S+?)\s+Mapping:\s*OK", re.IGNORECASE)
_NULL_SESSION = re.compile(r"allows sessions using username ''|null session", re.IGNORECASE)
_DOMAIN = re.compile(r"(?:Domain Name|Workgroup|Domain/Workgroup)\s*:\s*(\S+)", re.IGNORECASE)


def parse(result: ToolResult, target: str) -> list[Finding]:
    text = result.stdout
    if not text.strip():
        return []
    findings: list[Finding] = []

    if _NULL_SESSION.search(text):
        findings.append(
            Finding(
                title=f"SMB null session permitida em {target}",
                severity=Severity.MEDIUM,
                affected_asset=f"{target}:445",
                source_tool=TOOL,
                description=(
                    "O serviço SMB/Samba aceita sessão anônima (null session), permitindo "
                    "enumeração de usuários, shares e políticas sem credencial."
                ),
                evidence="enum4linux: null session aceita",
                confidence=Confidence.FIRM,
                cwe="CWE-287",  # Improper Authentication (categoria, não CVE)
                attack_technique="T1135",  # Network Share Discovery
                references=["https://attack.mitre.org/techniques/T1135/"],
            )
        )

    users = sorted({m.group(1).strip() for m in _USER.finditer(text) if m.group(1).strip()})
    if users:
        sample = ", ".join(users[:20]) + (" …" if len(users) > 20 else "")
        findings.append(
            Finding(
                title=f"{len(users)} usuário(s) SMB enumerado(s) em {target}",
                severity=Severity.LOW,
                affected_asset=f"{target}:445",
                source_tool=TOOL,
                description=f"Usuários descobertos via SMB: {sample}",
                evidence=sample[:500],
                confidence=Confidence.FIRM,
                attack_technique="T1087",  # Account Discovery
                references=["https://attack.mitre.org/techniques/T1087/"],
            )
        )

    for host, share in {(m.group(1), m.group(2)) for m in _SHARE_OK.finditer(text)}:
        findings.append(
            Finding(
                title=f"Share SMB acessível: {share}",
                severity=Severity.LOW,
                affected_asset=f"{host}/{share}",
                source_tool=TOOL,
                description=f"Compartilhamento SMB '{share}' mapeável em {host}.",
                evidence=f"//{host}/{share} Mapping: OK",
                confidence=Confidence.FIRM,
                attack_technique="T1135",
                references=["https://attack.mitre.org/techniques/T1135/"],
            )
        )

    dom = _DOMAIN.search(text)
    if dom:
        findings.append(
            Finding(
                title=f"Domínio/Workgroup SMB: {dom.group(1)}",
                severity=Severity.INFO,
                affected_asset=f"{target}:445",
                source_tool=TOOL,
                description=f"Domínio/Workgroup identificado via SMB: {dom.group(1)}.",
                evidence=dom.group(0),
                confidence=Confidence.FIRM,
                attack_technique="T1087",
            )
        )
    return findings
