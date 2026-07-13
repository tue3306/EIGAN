"""Parser do whatweb: JSON de plugins detectados → finding de fingerprint.

whatweb emite um array JSON; cada item traz ``plugins`` (mapa nome→detalhes). Um
serviço vivo vira UM finding informativo com as tecnologias no título (para a
cascata casar, ex.: "WordPress" → wpscan) e a evidência completa. Nada é inventado:
só o que a ferramenta reportou (§3.1).
"""

from __future__ import annotations

import json

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "whatweb"

# Plugins do whatweb que são metadados, não "tecnologia" — fora do título.
_NOISE = {"Country", "IP", "Title", "HTTPServer", "Cookies", "HttpOnly", "UncommonHeaders"}


def _tech_list(plugins: dict) -> list[str]:
    techs: list[str] = []
    for name, detail in plugins.items():
        if name in _NOISE:
            continue
        version = ""
        if isinstance(detail, dict):
            ver = detail.get("version") or detail.get("string")
            if isinstance(ver, list) and ver:
                version = str(ver[0])
        techs.append(f"{name} {version}".strip())
    return techs


def parse(result: ToolResult, target: str) -> list[Finding]:
    raw = result.stdout.strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]

    findings: list[Finding] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        plugins = item.get("plugins") or {}
        if not isinstance(plugins, dict) or not plugins:
            continue
        asset = str(item.get("target") or target)
        techs = _tech_list(plugins)
        server = ""
        if isinstance(plugins.get("HTTPServer"), dict):
            s = plugins["HTTPServer"].get("string")
            if isinstance(s, list) and s:
                server = str(s[0])
        label = ", ".join(techs) if techs else (server or "tecnologias web")
        findings.append(
            Finding(
                title=f"Tecnologias web: {label}"[:180],
                severity=Severity.INFO,
                affected_asset=asset,
                source_tool=TOOL,
                description=(
                    "Fingerprint de tecnologias/CMS da aplicação web "
                    f"({'servidor ' + server + '; ' if server else ''}"
                    f"{len(plugins)} plugin(s) do whatweb reconhecidos)."
                ),
                evidence=raw[:1000],
                confidence=Confidence.FIRM,
                attack_technique="T1592.002",  # Gather Victim Host Information: Software
                references=["https://attack.mitre.org/techniques/T1592/002/"],
            )
        )
    return findings
