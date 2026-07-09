"""Execução de scan compartilhada entre o comando ``scan`` e o wizard.

Centraliza a sequência: aceite de termo (1ª execução) → escopo (arquivo ou
efêmero) → consent inline → risco (EPSS/KEV offline por padrão) → orquestração.
Assim CLI e wizard não duplicam a política de segurança.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..engine.feeds import FeedCache
from ..engine.orchestrator import Orchestrator, ScanReport
from ..engine.risk import RiskScorer
from ..findings.store import FindingStore
from ..perspective import Perspective
from ..security.consent import ConsentDenied, ConsentGate
from ..security.onboarding import accept_terms, build_scope


class SessionAborted(Exception):
    """Fluxo interrompido por recusa de termo/consentimento (não é erro técnico)."""


@dataclass
class ScanOutcome:
    report: ScanReport
    feeds_meta: dict


def feeds_meta(feeds: FeedCache) -> dict:
    """Metadados de procedência dos feeds para o relatório (datas ou vazio)."""
    return {"kev": feeds.kev_date() if feeds.kev_available else "", "epss": feeds.epss_date()}


def execute_scan(
    *,
    targets: list[str],
    perspective: Perspective | None,
    profile: str,
    scope_path: str | None,
    db: str,
    assume_yes: bool,
    override_perspective: bool,
    online_enrich: bool,
    progress=None,
    input_fn=input,
    echo=print,
) -> ScanOutcome:
    if not accept_terms(assume_yes=assume_yes, input_fn=input_fn, echo=echo):
        raise SessionAborted("Termo de uso não aceito.")

    # Resolve a perspectiva: explícita > do scope.yaml > external (padrão §F).
    scope = build_scope(scope_path, targets, perspective or Perspective.EXTERNAL)
    resolved = perspective or scope.perspective

    try:
        ConsentGate(scope.engagement, targets).require(assume_yes=assume_yes, input_fn=input_fn)
    except ConsentDenied as exc:
        raise SessionAborted(str(exc)) from exc

    feeds = FeedCache.load()
    risk = RiskScorer(feeds, online=online_enrich)

    store = FindingStore(db)
    orch = Orchestrator(store=store, risk=risk)
    report = orch.run(
        targets,
        scope=scope,
        perspective=resolved,
        profile=profile,
        override_perspective=override_perspective,
        progress=progress,
    )
    return ScanOutcome(report=report, feeds_meta=feeds_meta(feeds))
