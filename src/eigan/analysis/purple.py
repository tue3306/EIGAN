"""Purple team — correlação ataque×detecção (ADR-0008, Pilar Purple).

Cruza o que o **Red** encontrou/exercitou (técnicas ATT&CK dos findings ofensivos)
com o que o **Blue** é capaz de detectar (técnicas das detecções defensivas —
hoje o log-analysis). O resultado é uma matriz de cobertura por técnica:

* **covered** — a técnica foi atacada E há detecção correspondente (defesa vê).
* **gap** (ponto cego) — a técnica foi atacada mas NÃO há detecção → o achado mais
  acionável do Purple: "seu recon exercitou T1190, mas nada detecta isso".
* **detection_only** — há detecção sem ataque correlato observado (cobertura ok).

Grounding (§3.1): só correlaciona técnicas que os findings realmente carregam
(``attack_technique``); nomes/táticas vêm do catálogo curado (analysis/attack.py).
Determinístico — a IA só NARRA os gaps (opcional), nunca inventa cobertura.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ..findings.schema import Finding
from .attack import load_catalog

# Ferramentas cujas saídas são DETECÇÕES (Blue), não ataques (Red). Ampliar quando
# novos plugins blue entrarem. A API enriquece isto a partir do registry (categoria).
DEFAULT_DETECTION_TOOLS = frozenset({"log-analysis"})

_STATUS_ORDER = {"gap": 0, "covered": 1, "detection_only": 2}


def _parent(technique: str) -> str:
    """Técnica-pai de uma (sub)técnica ATT&CK: 'T1595.003' → 'T1595'.

    A correlação de cobertura é feita no nível da FAMÍLIA: uma detecção de T1595
    (Active Scanning) cobre um ataque via T1595.003 (uma sub-técnica dela). É o
    padrão em análises de cobertura ATT&CK (evita falsos pontos cegos por
    granularidade diferente entre Red e Blue)."""
    return technique.split(".", 1)[0].strip()


@dataclass
class TechniqueCorrelation:
    """Correlação de UMA técnica ATT&CK entre ataque e detecção."""

    technique: str
    name: str
    tactic: str
    url: str
    attacked: int  # nº de findings Red com esta técnica
    detected: int  # nº de detecções Blue com esta técnica
    status: str  # covered | gap | detection_only


@dataclass
class PurpleReport:
    correlations: list[TechniqueCorrelation] = field(default_factory=list)
    covered: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)  # técnicas atacadas SEM detecção
    detection_only: list[str] = field(default_factory=list)
    coverage_pct: float = 0.0  # covered / (covered + gaps)
    red_techniques: int = 0
    blue_techniques: int = 0
    red_findings: int = 0
    blue_findings: int = 0


def split_findings(
    findings: list[Finding], detection_tools: frozenset[str] = DEFAULT_DETECTION_TOOLS
) -> tuple[list[Finding], list[Finding]]:
    """Separa findings em (red=ataque, blue=detecção) pela ferramenta de origem."""
    red = [f for f in findings if f.source_tool not in detection_tools]
    blue = [f for f in findings if f.source_tool in detection_tools]
    return red, blue


def correlate(
    red_findings: list[Finding],
    blue_findings: list[Finding],
    *,
    catalog: dict[str, dict] | None = None,
) -> PurpleReport:
    """Correlaciona técnicas Red×Blue e devolve a matriz de cobertura + gaps."""
    cat = catalog if catalog is not None else load_catalog()
    # correlaciona no nível da família (técnica-pai) — ver `_parent`.
    red_tech = Counter(_parent(f.attack_technique) for f in red_findings if f.attack_technique)
    blue_tech = Counter(_parent(f.attack_technique) for f in blue_findings if f.attack_technique)

    correlations: list[TechniqueCorrelation] = []
    covered: list[str] = []
    gaps: list[str] = []
    detection_only: list[str] = []
    for tid in sorted(set(red_tech) | set(blue_tech)):
        entry = cat.get(tid, {})
        attacked, detected = red_tech.get(tid, 0), blue_tech.get(tid, 0)
        if attacked and detected:
            status = "covered"
            covered.append(tid)
        elif attacked and not detected:
            status = "gap"
            gaps.append(tid)
        else:
            status = "detection_only"
            detection_only.append(tid)
        correlations.append(
            TechniqueCorrelation(
                technique=tid,
                name=str(entry.get("name", tid)),
                tactic=str(entry.get("tactic", "")),
                url=str(entry.get("url", "")),
                attacked=attacked,
                detected=detected,
                status=status,
            )
        )

    # gaps primeiro (mais acionável), depois covered, depois detection_only.
    correlations.sort(key=lambda c: (_STATUS_ORDER[c.status], -(c.attacked + c.detected)))
    denom = len(covered) + len(gaps)
    coverage_pct = round(100.0 * len(covered) / denom, 1) if denom else 0.0
    return PurpleReport(
        correlations=correlations,
        covered=covered,
        gaps=gaps,
        detection_only=detection_only,
        coverage_pct=coverage_pct,
        red_techniques=len(red_tech),
        blue_techniques=len(blue_tech),
        red_findings=len(red_findings),
        blue_findings=len(blue_findings),
    )


def correlate_findings(
    findings: list[Finding],
    *,
    detection_tools: frozenset[str] = DEFAULT_DETECTION_TOOLS,
    catalog: dict[str, dict] | None = None,
) -> PurpleReport:
    """Conveniência: separa uma lista mista (red+blue) e correlaciona."""
    red, blue = split_findings(findings, detection_tools)
    return correlate(red, blue, catalog=catalog)


def purple_context(report: PurpleReport) -> str:
    """Resumo textual grounded do Purple para a IA narrar os gaps (opcional)."""
    lines = [
        f"Cobertura de detecção: {report.coverage_pct}% "
        f"({len(report.covered)} de {len(report.covered) + len(report.gaps)} técnicas atacadas).",
        "",
        "PONTOS CEGOS (técnicas atacadas SEM detecção):",
    ]
    gap_rows = [c for c in report.correlations if c.status == "gap"]
    if gap_rows:
        for c in gap_rows:
            lines.append(
                f"  - {c.technique} {c.name} [{c.tactic or 'tática?'}] — {c.attacked}× no Red"
            )
    else:
        lines.append("  (nenhum — toda técnica atacada tem detecção correspondente)")
    covered_rows = [c for c in report.correlations if c.status == "covered"]
    if covered_rows:
        lines.append("")
        lines.append("COBERTAS (atacadas E detectadas):")
        for c in covered_rows:
            lines.append(f"  - {c.technique} {c.name} — Red {c.attacked}× / Blue {c.detected}×")
    return "\n".join(lines)
