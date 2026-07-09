"""Conformidade básica (Blue) — mapeamento INDICATIVO de findings a controles.

Associa cada finding (por CWE) a **referências de conformidade** (OWASP/NIST/CIS)
carregadas de um mapa auditável (``knowledge/compliance/mappings.yaml``), cada
uma com URL oficial. **Não é atestação de conformidade** — é um ponto de partida
que o time amplia. Findings sem entrada aparecem como ``unmapped`` (não se
inventa cobertura).

Determinístico. A auditoria de hardening completa (CIS Benchmarks por SO) é um
plugin de roadmap (``plugins/blue/*``).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..findings.schema import Finding

_MAP = Path(__file__).resolve().parents[3] / "knowledge" / "compliance" / "mappings.yaml"


@dataclass
class ComplianceRef:
    framework: str
    ref: str
    url: str


@dataclass
class ComplianceItem:
    finding_title: str
    cwe: str
    refs: list[ComplianceRef]


@dataclass
class ComplianceReport:
    items: list[ComplianceItem] = field(default_factory=list)
    frameworks: dict[str, int] = field(default_factory=dict)  # framework → nº de findings
    unmapped: int = 0
    indicative: bool = True  # sempre: requer validação por especialista


def load_mappings(path: Path | None = None) -> dict[str, list[dict]]:
    p = path or _MAP
    if not p.exists():
        return {}
    data = yaml.safe_load(p.read_text()) or {}
    return data.get("mappings", {}) if isinstance(data, dict) else {}


def assess_compliance(findings: list[Finding],
                      mappings: dict[str, list[dict]] | None = None) -> ComplianceReport:
    table = mappings if mappings is not None else load_mappings()
    items: list[ComplianceItem] = []
    fw_counter: Counter[str] = Counter()
    unmapped = 0

    for f in findings:
        entries = table.get(f.cwe or "", [])
        if not entries:
            unmapped += 1
            continue
        refs = [ComplianceRef(framework=str(e.get("framework", "")),
                              ref=str(e.get("ref", "")), url=str(e.get("url", "")))
                for e in entries]
        items.append(ComplianceItem(finding_title=f.title, cwe=f.cwe or "", refs=refs))
        for r in refs:
            fw_counter[r.framework] += 1

    return ComplianceReport(items=items, frameworks=dict(fw_counter), unmapped=unmapped)
