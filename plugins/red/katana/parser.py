"""Parser do katana: URLs rastreadas → finding da superfície web descoberta.

Saída = uma URL por linha. Produz UM finding informativo com a contagem de URLs e,
principalmente, as URLs **com parâmetros** (a superfície de injeção que orienta o
scan de vulnerabilidades). Só o que a ferramenta descobriu — nada inventado (§3.1).
"""

from __future__ import annotations

from urllib.parse import urlparse

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "katana"
_MAX_EVIDENCE = 40  # nº de URLs paramétricas listadas na evidência


def parse(result: ToolResult, target: str) -> list[Finding]:
    urls: list[str] = []
    seen: set[str] = set()
    for line in result.stdout.splitlines():
        u = line.strip()
        if not u or not u.lower().startswith(("http://", "https://")) or u in seen:
            continue
        seen.add(u)
        urls.append(u)
    if not urls:
        return []

    params = [u for u in urls if "?" in u and urlparse(u).query]
    host = urlparse(target).hostname or target
    evidence = "\n".join(params[:_MAX_EVIDENCE]) if params else "\n".join(urls[:_MAX_EVIDENCE])
    return [
        Finding(
            title=f"Superfície web: {len(urls)} URL(s), {len(params)} com parâmetros",
            severity=Severity.INFO,
            affected_asset=host,
            source_tool=TOOL,
            description=(
                f"katana rastreou {len(urls)} URL(s) em {host}; "
                f"{len(params)} carregam parâmetros (candidatas a teste de injeção)."
            ),
            evidence=evidence[:2000],
            confidence=Confidence.FIRM,
            attack_technique="T1595.001",  # Active Scanning: Scanning IP Blocks/Wordlist
            references=["https://attack.mitre.org/techniques/T1595/"],
        )
    ]
