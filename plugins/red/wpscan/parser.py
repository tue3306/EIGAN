"""Parser do wpscan: JSON → findings de WordPress.

Extrai versão do WP (disclosure), achados interessantes (readme/xmlrpc/backups),
usuários enumerados e vulnerabilidades conhecidas (quando o feed WPScan responde).
Vulnerabilidade confirmada pela ferramenta → HIGH; enumeração → INFO/LOW. CVEs
citados pelo wpscan viram referência sem fabricar score (§3.1).
"""

from __future__ import annotations

import json

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "wpscan"


def _vuln_findings(vulns: list, asset: str, ctx: str) -> list[Finding]:
    out: list[Finding] = []
    for v in vulns or []:
        if not isinstance(v, dict):
            continue
        title = str(v.get("title") or "vulnerabilidade")
        refs = v.get("references") or {}
        cves = [f"CVE-{c}" for c in (refs.get("cve") or [])]
        urls = [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:3]] or [
            "https://wpscan.com/"
        ]
        out.append(
            Finding(
                title=f"WordPress: {title}"[:180],
                severity=Severity.HIGH,
                affected_asset=asset,
                source_tool=TOOL,
                owasp="A06:2021",  # Vulnerable and Outdated Components
                description=f"{ctx}: {title}" + (f" ({', '.join(cves)})" if cves else ""),
                evidence=json.dumps(v, ensure_ascii=False)[:400],
                confidence=Confidence.FIRM,
                attack_technique="T1190",
                references=urls,
            )
        )
    return out


def parse(result: ToolResult, target: str) -> list[Finding]:
    raw = (result.stdout or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []

    findings: list[Finding] = []
    asset = str(data.get("target_url") or target)

    version = data.get("version") or {}
    if isinstance(version, dict) and version.get("number"):
        findings.append(
            Finding(
                title=f"WordPress {version['number']} detectado",
                severity=Severity.INFO,
                affected_asset=asset,
                source_tool=TOOL,
                description=f"Versão do WordPress identificada: {version['number']}.",
                evidence=str(version.get("found_by", ""))[:200],
                confidence=Confidence.FIRM,
                attack_technique="T1592.002",
                references=["https://wpscan.com/"],
            )
        )
        findings += _vuln_findings(version.get("vulnerabilities"), asset, "WordPress core")

    for name, plugin in (data.get("plugins") or {}).items():
        if isinstance(plugin, dict):
            findings += _vuln_findings(plugin.get("vulnerabilities"), asset, f"Plugin {name}")

    for f in data.get("interesting_findings") or []:
        if isinstance(f, dict) and f.get("to_s"):
            findings.append(
                Finding(
                    title=f"WP: {f['to_s']}"[:180],
                    severity=Severity.INFO,
                    affected_asset=str(f.get("url") or asset),
                    source_tool=TOOL,
                    description=str(f.get("to_s")),
                    evidence=str(f.get("type", "")),
                    confidence=Confidence.TENTATIVE,
                    attack_technique="T1592.002",
                    references=["https://wpscan.com/"],
                )
            )

    users = list((data.get("users") or {}).keys())
    if users:
        findings.append(
            Finding(
                title=f"WordPress: {len(users)} usuário(s) enumerado(s)",
                severity=Severity.LOW,
                affected_asset=asset,
                source_tool=TOOL,
                cwe="CWE-200",
                description=f"Usuários enumeráveis: {', '.join(users[:10])}.",
                evidence=", ".join(users[:20])[:300],
                confidence=Confidence.FIRM,
                attack_technique="T1589.001",  # Gather Victim Identity: Credentials
                references=["https://owasp.org/www-community/attacks/Username_enumeration"],
            )
        )
    return findings
