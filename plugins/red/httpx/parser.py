"""Parser do httpx (ProjectDiscovery): serviços web vivos + tecnologias."""

from __future__ import annotations

import json

from vulnforge.engine.base import ToolResult
from vulnforge.findings.schema import Confidence, Finding, Severity

TOOL = "httpx"


def parse(result: ToolResult, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = obj.get("url") or obj.get("input") or target
        status = obj.get("status_code") or obj.get("status-code")
        tech = obj.get("tech") or obj.get("technologies") or []
        title = obj.get("title", "")
        server = obj.get("webserver", "")
        desc = f"Serviço web vivo em {url} (status {status})."
        if tech:
            desc += f" Tecnologias: {', '.join(tech)}."
        findings.append(
            Finding(
                title=f"Web vivo: {url}",
                severity=Severity.INFO,
                affected_asset=url,
                source_tool=TOOL,
                description=desc,
                evidence=json.dumps({"title": title, "server": server, "tech": tech})[:500],
                confidence=Confidence.FIRM,
            )
        )
    return findings
