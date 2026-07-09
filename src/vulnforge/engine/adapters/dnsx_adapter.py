"""Adapter para dnsx (ProjectDiscovery) — resolução/validação de hosts vivos.

Elo que faltava (Parte 2 do escopo): valida quais subdomínios/hosts respondem
DNS antes do httpx/naabu, evitando trabalho contra alvos mortos. Lê a lista de
hosts via stdin (``-l`` aceita arquivo ou stdin). Schema JSONL confirmado
executando ``dnsx -json`` de verdade (campos: host, a, status_code, ...).

Recon: alimenta o inventário de assets (não gera Finding de vulnerabilidade).
"""

from __future__ import annotations

import json

from ...findings.schema import Confidence, Finding, Severity
from ...perspective import Perspective
from ..base import BaseToolAdapter, ToolResult


class DnsxAdapter(BaseToolAdapter):
    binary = "dnsx"
    name = "dnsx"
    supported_perspectives = (Perspective.EXTERNAL, Perspective.INTERNAL)
    target_via_stdin = True        # recebe o host pela entrada padrão
    version_source = "dnsx -version  # VERIFICAR"
    license = "VERIFICAR"          # MIT (projectdiscovery) — confirmar
    commercial_use = "verify"

    def build_args(self, target: str, **_) -> list[str]:
        # host chega via stdin (target_via_stdin); -a resolve registros A.
        return ["-json", "-silent", "-a", "-resp"]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = obj.get("host", target)
            a_records = obj.get("a") or []
            status = obj.get("status_code", "")
            # host "vivo" = resolveu (NOERROR) com pelo menos um registro A.
            if status and status != "NOERROR" and not a_records:
                continue
            findings.append(
                Finding(
                    title=f"Host DNS ativo: {host}",
                    severity=Severity.INFO,
                    affected_asset=host,
                    source_tool=self.name,
                    description=f"{host} resolveu para {', '.join(a_records) or 'registro DNS'}.",
                    evidence=line[:500],
                    confidence=Confidence.FIRM,
                )
            )
        return findings
