"""Inventário de ativos (Blue) — o que existe, derivado dos findings.

Agrega, por host, as portas/serviços expostos, os endpoints web vivos e as
perspectivas em que o ativo foi visto. Base para o dashboard e para gestão de
superfície. Determinístico; não infere nada além do que os findings dizem.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from ..findings.schema import Finding
from ..perspective import extract_host

# "10.0.0.5:80" → porta; ignora URLs (que viram web_endpoints).
_HOSTPORT = re.compile(r"^[^/]+:(\d{1,5})$")


@dataclass
class Asset:
    host: str
    perspectives: list[str] = field(default_factory=list)
    ports: list[str] = field(default_factory=list)         # ex.: "80", "443"
    web_endpoints: list[str] = field(default_factory=list)  # URLs vivas
    finding_count: int = 0
    max_risk: float = 0.0


def build_inventory(findings: list[Finding]) -> list[Asset]:
    hosts: dict[str, Asset] = defaultdict(lambda: Asset(host=""))
    perspectives: dict[str, set[str]] = defaultdict(set)
    ports: dict[str, set[str]] = defaultdict(set)
    web: dict[str, set[str]] = defaultdict(set)

    for f in findings:
        host = extract_host(f.affected_asset)
        a = hosts[host]
        a.host = host
        a.finding_count += 1
        a.max_risk = max(a.max_risk, f.risk_rank)
        perspectives[host].add(f.perspective.value)

        m = _HOSTPORT.match(f.affected_asset.strip())
        if m:
            ports[host].add(m.group(1))
        if "://" in f.affected_asset:
            web[host].add(f.affected_asset)

    for host, a in hosts.items():
        a.perspectives = sorted(perspectives[host])
        a.ports = sorted(ports[host], key=lambda p: int(p))
        a.web_endpoints = sorted(web[host])

    return sorted(hosts.values(), key=lambda a: a.max_risk, reverse=True)


def summarize(inventory: list[Asset]) -> dict:
    """Números agregados para o dashboard/relatório executivo."""
    return {
        "assets": len(inventory),
        "with_open_ports": sum(1 for a in inventory if a.ports),
        "with_web": sum(1 for a in inventory if a.web_endpoints),
        "cross_perspective": sum(1 for a in inventory if len(a.perspectives) > 1),
        "total_ports": sum(len(a.ports) for a in inventory),
    }
