"""Parser do ffuf: resultados de fuzzing → findings de conteúdo descoberto.

Aceita tanto o JSON único (``{"results": [...]}``) quanto NDJSON (uma linha por
achado). Endpoints sensíveis (``.git``, ``.env``, backups, ``wp-config``) que
respondem 200 sobem de severidade — é exposição real, não só um path a mais.
Só o que a ferramenta reportou (§3.1).
"""

from __future__ import annotations

import json

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "ffuf"

# Trechos de URL que indicam exposição sensível (peso maior quando acessível).
_SENSITIVE = (
    ".git",
    ".env",
    ".htpasswd",
    ".htaccess",
    "wp-config",
    "config.php",
    "phpinfo",
    "backup",
    ".sql",
    "dump",
    "id_rsa",
    "web.config",
    ".bak",
)


def _results(raw: str) -> list[dict]:
    raw = raw.strip()
    if not raw:
        return []
    try:  # 1) JSON único: {"results": [...]} ou lista
        obj = json.loads(raw)
        if isinstance(obj, dict) and isinstance(obj.get("results"), list):
            return [r for r in obj["results"] if isinstance(r, dict)]
        if isinstance(obj, list):
            return [r for r in obj if isinstance(r, dict)]
        if isinstance(obj, dict):
            return [obj]
    except json.JSONDecodeError:
        pass
    out: list[dict] = []  # 2) NDJSON (uma linha por achado)
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(r, dict):
            out.append(r)
    return out


def _severity(url: str, status) -> Severity:
    low = url.lower()
    if status == 200 and any(s in low for s in _SENSITIVE):
        return Severity.MEDIUM  # arquivo sensível acessível
    return Severity.INFO


def parse(result: ToolResult, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for r in _results(result.stdout):
        url = str(r.get("url") or "")
        status = r.get("status")
        if not url or status is None:
            continue
        length = r.get("length")
        sev = _severity(url, status)
        findings.append(
            Finding(
                title=f"Conteúdo descoberto: {url} [{status}]"[:180],
                severity=sev,
                affected_asset=url,
                source_tool=TOOL,
                description=(
                    f"ffuf encontrou {url} respondendo HTTP {status}"
                    + (f" ({length} bytes)" if length is not None else "")
                    + ("; caminho sensível acessível." if sev is Severity.MEDIUM else ".")
                ),
                evidence=json.dumps(r, ensure_ascii=False)[:500],
                confidence=Confidence.FIRM,
                attack_technique="T1595.003",  # Active Scanning: Wordlist Scanning
                references=["https://attack.mitre.org/techniques/T1595/003/"],
            )
        )
    return findings
