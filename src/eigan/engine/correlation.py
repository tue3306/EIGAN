"""Correlation Engine — visão por ativo + cadeias de ataque possíveis (§D).

Une resultados de plugins diferentes num mesmo **ativo** (host), preservando a
rastreabilidade da origem (perspectiva + ferramenta de cada finding — nada é
fundido cegamente). Identifica uma **possível cadeia de ataque** ligando
exposição → superfície → vulnerabilidade no mesmo host.

Determinístico e honesto: a cadeia é uma **heurística rotulada como tal**, não
uma afirmação de exploração. Serve à priorização e à narrativa do relatório.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ..findings.schema import Finding, Severity
from ..perspective import extract_host

# papel de cada ferramenta na progressão de um ataque (rank crescente).
# Ferramenta desconhecida entra como superfície (rank 3) — neutro e seguro.
_ROLE: dict[str, tuple[int, str]] = {
    "subfinder": (1, "Subdomínio exposto"),
    "dnsx": (1, "Host DNS ativo"),
    "naabu": (2, "Porta aberta"),
    "nmap": (2, "Porta/serviço exposto"),
    "httpx": (3, "Serviço web acessível"),
    "nuclei": (4, "Vulnerabilidade detectada"),
}
_DEFAULT_ROLE = (3, "Superfície")


@dataclass
class AssetCorrelation:
    """Tudo que se sabe sobre um ativo (host), agregado de várias ferramentas."""

    asset: str
    findings: list[Finding]
    perspectives: list[str]
    max_risk: float
    severity_counts: dict[str, int] = field(default_factory=dict)
    attack_chain: list[str] = field(default_factory=list)

    @property
    def cross_perspective(self) -> bool:
        """Visto de fora E de dentro? (correlação Outside-In × Inside-Out)."""
        return len(self.perspectives) > 1


def _build_chain(findings: list[Finding]) -> list[str]:
    """Monta uma cadeia possível: um passo por papel presente, em ordem de
    progressão. Só retorna cadeia quando há progressão real (≥2 papéis)."""
    by_rank: dict[int, tuple[str, Finding]] = {}
    for f in findings:
        rank, label = _ROLE.get(f.source_tool, _DEFAULT_ROLE)
        # mantém, por papel, o finding de maior risco como representante.
        cur = by_rank.get(rank)
        if cur is None or f.risk_rank > cur[1].risk_rank:
            by_rank[rank] = (label, f)
    if len(by_rank) < 2:
        return []
    steps = []
    for rank in sorted(by_rank):
        label, f = by_rank[rank]
        steps.append(f"{label}: {f.title}")
    return steps


def correlate_assets(findings: list[Finding]) -> list[AssetCorrelation]:
    """Agrupa findings por host e monta a visão correlacionada, ordenada por risco."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        host = extract_host(f.affected_asset)
        groups.setdefault(host, []).append(f)

    out: list[AssetCorrelation] = []
    for host, fs in groups.items():
        perspectives = sorted({f.perspective.value for f in fs})
        max_risk = max((f.risk_rank for f in fs), default=0.0)
        counts = Counter(f.severity.value for f in fs)
        ordered = sorted(fs, key=lambda f: f.risk_rank, reverse=True)
        out.append(
            AssetCorrelation(
                asset=host,
                findings=ordered,
                perspectives=perspectives,
                max_risk=max_risk,
                severity_counts={s.value: counts.get(s.value, 0) for s in Severity},
                attack_chain=_build_chain(fs),
            )
        )
    out.sort(key=lambda a: a.max_risk, reverse=True)
    return out
