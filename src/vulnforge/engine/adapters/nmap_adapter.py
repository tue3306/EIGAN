"""Adapter para nmap — descoberta de portas/serviços.

Faz o parse do XML nativo do nmap (``-oX -``), formato estável e documentado
(https://nmap.org/book/nmap-dtd.html), em vez de raspar texto. Portas abertas
viram findings informativos/correlacionáveis; a análise de vulnerabilidade em
si vem de outras ferramentas (nuclei etc.).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from ...findings.schema import Confidence, Finding, Severity
from ..base import BaseToolAdapter, ToolResult


class NmapAdapter(BaseToolAdapter):
    binary = "nmap"
    name = "nmap"

    def build_args(self, target: str, *, ports: str | None = None, scripts: bool = False,
                   **_) -> list[str]:
        args = ["-sV", "-oX", "-", "-Pn"]
        if ports:
            # `ports` é validado/limitado no orquestrador; ainda assim é um token isolado
            args += ["-p", ports]
        if scripts:
            args += ["--script", "default,vuln"]
        args.append(target)
        return args

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        findings: list[Finding] = []
        if not result.stdout.strip():
            return findings
        try:
            root = ET.fromstring(result.stdout)
        except ET.ParseError:
            return findings

        for host in root.findall("host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr") if addr_el is not None else target
            for port in host.findall(".//port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = port.get("portid")
                proto = port.get("protocol", "tcp")
                svc = port.find("service")
                svc_name = svc.get("name", "unknown") if svc is not None else "unknown"
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                banner = f"{product} {version}".strip()

                findings.append(
                    Finding(
                        title=f"Porta aberta {portid}/{proto} ({svc_name})",
                        severity=Severity.INFO,
                        affected_asset=f"{addr}:{portid}",
                        source_tool=self.name,
                        description=(
                            f"Serviço '{svc_name}' exposto em {addr}:{portid}/{proto}."
                            + (f" Banner: {banner}." if banner else "")
                        ),
                        evidence=result.stdout[:2000],
                        # versão detectada NÃO é confirmada contra base de CVE aqui:
                        confidence=Confidence.FIRM if banner else Confidence.TENTATIVE,
                        attack_technique="T1046",  # Network Service Discovery (MITRE ATT&CK)
                        references=["https://attack.mitre.org/techniques/T1046/"],
                    )
                )
        return findings
