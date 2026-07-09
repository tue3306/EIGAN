"""Risk Engine — pontuação composta de risco (ADR-0002).

Combina o que é **verificável localmente** (CVSS) com sinais externos de fonte
oficial (EPSS/KEV). Regra inegociável: EPSS/KEV só entram como fato se o feed foi
consultado (:mod:`vulnforge.engine.feeds`); do contrário saem ``UNVERIFIED`` e o
score usa apenas o verificável. **Nunca** se fabrica número.

A fórmula é intencionalmente simples e auditável (transparência > sofisticação):
o ``rationale`` de cada :class:`~vulnforge.findings.schema.RiskScore` explica em
texto quais sinais entraram e de onde vieram (``provenance``).
"""

from __future__ import annotations

import re

from ..findings.schema import Finding, RiskScore, Severity
from .feeds import FeedCache, _http_get

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# base de risco quando não há CVSS: deriva da severidade normalizada (0-100).
_SEV_BASE: dict[Severity, float] = {
    Severity.INFO: 5.0,
    Severity.LOW: 25.0,
    Severity.MEDIUM: 50.0,
    Severity.HIGH: 75.0,
    Severity.CRITICAL: 90.0,
}


def cve_ids(finding: Finding) -> set[str]:
    """Extrai identificadores CVE das evidências do finding (título, descrição,
    evidência e referências). Não infere nada — só o que está escrito."""
    blob = " ".join([
        finding.title, finding.description, finding.evidence, *finding.references,
    ])
    return {m.upper() for m in _CVE_RE.findall(blob)}


class RiskScorer:
    """Pontua findings. ``online=True`` permite buscar EPSS na FIRST.org para os
    CVEs do lote (cacheado); por padrão é **offline** (usa só o cache existente),
    preservando determinismo."""

    def __init__(self, feeds: FeedCache | None = None, *, online: bool = False,
                 getter=_http_get) -> None:
        self._feeds = feeds
        self._online = online
        self._getter = getter

    def score(self, findings: list[Finding]) -> list[Finding]:
        if self._online and self._feeds is not None:
            all_cves = sorted({c for f in findings for c in cve_ids(f)})
            if all_cves:
                try:
                    self._feeds.update_epss(all_cves, getter=self._getter)
                except Exception:  # noqa: BLE001 — falha de rede não impede o scoring offline
                    pass
        for f in findings:
            f.risk = self._score_one(f)
        return findings

    def _base(self, f: Finding) -> float:
        if f.cvss is not None:
            return f.cvss.score * 10.0
        return _SEV_BASE[f.severity]

    def _score_one(self, f: Finding) -> RiskScore:
        cves = cve_ids(f)
        score = self._base(f)
        provenance: dict[str, str] = {}
        rationale: list[str] = []

        if f.cvss is not None:
            provenance["cvss"] = f"CVSS {f.cvss.version} = {f.cvss.score}"
            rationale.append(f"CVSS {f.cvss.version} {f.cvss.score}")
        else:
            rationale.append(f"sem CVSS; base pela severidade '{f.severity.value}'")

        # ── KEV (catálogo completo: ausência = 'não consta', verificável) ─────────
        kev = False
        kev_verified = False
        if self._feeds is not None and self._feeds.kev_available:
            kev_verified = True
            kev = bool(cves & self._feeds.kev_cves)  # type: ignore[operator]
            provenance["kev"] = f"CISA KEV {self._feeds.kev_date()}".strip()
            if kev:
                rationale.append("consta na CISA KEV (exploração ativa conhecida)")
        else:
            provenance["kev"] = "UNVERIFIED (rode `vulnforge feeds update`)"

        # ── EPSS (por-CVE: ausência = desconhecido, não zero) ─────────────────────
        epss: float | None = None
        epss_verified = False
        if self._feeds is not None and cves:
            hits = [self._feeds.epss_scores[c] for c in cves if c in self._feeds.epss_scores]
            if hits:
                epss = max(hits)
                epss_verified = True
                provenance["epss"] = f"FIRST.org EPSS {self._feeds.epss_date()}".strip()
                rationale.append(f"EPSS {epss:.3f}")
        if epss is None:
            provenance["epss"] = "UNVERIFIED (" + ("sem CVE" if not cves else "feed não atualizado") + ")"

        # ── modificadores compostos (auditáveis) ──────────────────────────────────
        if epss is not None:
            score = min(100.0, score + epss * 20.0)  # EPSS alto eleva a prioridade
        exploit_available = kev if kev_verified else None
        if kev:
            score = min(100.0, max(score, 85.0) + 10.0)  # KEV domina a priorização

        return RiskScore(
            score=round(score, 1),
            epss=epss,
            epss_verified=epss_verified,
            kev=kev,
            kev_verified=kev_verified,
            exploit_available=exploit_available,
            rationale="; ".join(rationale),
            provenance=provenance,
        )
