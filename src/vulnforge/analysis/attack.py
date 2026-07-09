"""Mapa MITRE ATT&CK dos findings + gap analysis (Purple).

Correlaciona os findings às técnicas ATT&CK que eles já carregam
(``attack_technique``), usando um catálogo **curado e verificável**
(``knowledge/attack/techniques.yaml``) para resolver tática/nome/URL. Produz a
cobertura por tática e o *gap* (táticas do ATT&CK Enterprise sem nenhum sinal).

Honesto por construção: técnica sem entrada no catálogo aparece como
``unmapped`` (não se inventa a tática). O universo de táticas é o do ATT&CK
Enterprise (referência: https://attack.mitre.org/tactics/enterprise/).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..findings.schema import Finding

_CATALOG = Path(__file__).resolve().parents[3] / "knowledge" / "attack" / "techniques.yaml"

# Táticas do ATT&CK Enterprise, na ordem canônica (kill chain).
ENTERPRISE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


@dataclass
class TechniqueHit:
    technique: str
    name: str
    tactic: str
    url: str
    count: int


@dataclass
class AttackCoverage:
    hits: list[TechniqueHit] = field(default_factory=list)
    unmapped: list[str] = field(default_factory=list)   # técnicas sem catálogo
    tactics_covered: list[str] = field(default_factory=list)
    tactics_gap: list[str] = field(default_factory=list)


def load_catalog(path: Path | None = None) -> dict[str, dict]:
    p = path or _CATALOG
    if not p.exists():
        return {}
    data = yaml.safe_load(p.read_text()) or {}
    return data.get("techniques", {}) if isinstance(data, dict) else {}


def map_attack(findings: list[Finding], catalog: dict[str, dict] | None = None) -> AttackCoverage:
    cat = catalog if catalog is not None else load_catalog()
    counts = Counter(f.attack_technique for f in findings if f.attack_technique)

    hits: list[TechniqueHit] = []
    unmapped: list[str] = []
    covered: set[str] = set()
    for tid, n in sorted(counts.items()):
        entry = cat.get(tid)
        if not entry:
            unmapped.append(tid)
            continue
        tactic = str(entry.get("tactic", ""))
        hits.append(TechniqueHit(
            technique=tid, name=str(entry.get("name", tid)),
            tactic=tactic, url=str(entry.get("url", "")), count=n,
        ))
        if tactic:
            covered.add(tactic)

    hits.sort(key=lambda h: h.count, reverse=True)
    covered_ordered = [t for t in ENTERPRISE_TACTICS if t in covered]
    gap = [t for t in ENTERPRISE_TACTICS if t not in covered]
    return AttackCoverage(hits=hits, unmapped=unmapped,
                          tactics_covered=covered_ordered, tactics_gap=gap)
