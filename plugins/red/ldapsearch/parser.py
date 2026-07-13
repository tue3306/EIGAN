"""Parser do ldapsearch: LDIF do RootDSE → findings de exposição LDAP/AD.

Se o bind anônimo retorna o RootDSE (naming contexts, domínio), isso já é uma
exposição de informação (MEDIUM) — permite mapear o diretório/AD sem credencial.
Extrai os ``namingContexts`` (ex.: ``dc=corp,dc=local``) como evidência. Só o que
o servidor respondeu (§3.1).
"""

from __future__ import annotations

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "ldapsearch"


def _attrs(ldif: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in ldif.splitlines():
        line = line.rstrip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.lstrip(": ").strip()
        if key and val:
            out.setdefault(key, []).append(val)
    return out


def parse(result: ToolResult, target: str) -> list[Finding]:
    ldif = result.stdout or ""
    attrs = _attrs(ldif)
    contexts = attrs.get("namingContexts", [])
    # "result: 0 Success" ou a presença de namingContexts indicam bind anônimo OK.
    anon_ok = bool(contexts) or "result: 0 Success" in ldif
    if not anon_ok:
        return []

    domain = ", ".join(contexts) or "desconhecido"
    return [
        Finding(
            title="Bind anônimo LDAP/AD permitido (RootDSE exposto)",
            severity=Severity.MEDIUM,
            affected_asset=target,
            source_tool=TOOL,
            cwe="CWE-200",
            description=(
                "O servidor LDAP respondeu ao bind ANÔNIMO e expôs o RootDSE — "
                f"naming context(s): {domain}. Permite mapear o diretório/AD sem "
                "credencial (enumeração de domínio/estrutura)."
            ),
            evidence=("\n".join(f"{k}: {v[0]}" for k, v in attrs.items() if v))[:600],
            confidence=Confidence.FIRM,
            attack_technique="T1087.002",  # Account Discovery: Domain Account
            references=[
                "https://attack.mitre.org/techniques/T1087/002/",
                "https://cwe.mitre.org/data/definitions/200.html",
            ],
        )
    ]
