"""Execução de scan compartilhada entre o comando ``scan`` e o wizard.

Centraliza a sequência: aceite de termo (1ª execução) → escopo (arquivo ou
efêmero) → consent inline → risco (EPSS/KEV offline por padrão) → orquestração.
Assim CLI e wizard não duplicam a política de segurança.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

from ..engine.cognitive import CognitiveEngine, CognitiveReport, DecisionEntry, Goal, GoalKind

if TYPE_CHECKING:
    from ..engine.cognitive import CompletionPort
from ..engine.feeds import FeedCache
from ..engine.orchestrator import Orchestrator, ScanReport
from ..engine.registry import PluginRegistry
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


@dataclass
class PlanOutcome:
    """Resultado do comando ``plan`` (núcleo cognitivo, ADR-0007)."""

    goal: Goal
    planner_name: str
    ai_used: bool
    decisions: list[DecisionEntry]
    report: CognitiveReport | None = None  # None em dry-run (nada executado)
    suggestions: list = field(default_factory=list)


def plan_scan(
    *,
    goal_kind: GoalKind,
    targets: list[str],
    perspective: Perspective | None,
    profile: str,
    scope_path: str | None,
    db: str,
    assume_yes: bool,
    override_perspective: bool,
    online_enrich: bool,
    dry_run: bool,
    use_ai: bool,
    input_fn=input,
    echo=print,
) -> PlanOutcome:
    """Roda o núcleo cognitivo goal-driven (Planner → seleção → execução).

    ``dry_run`` mostra o plano e a seleção justificada **sem executar** — por isso
    não passa pelo consent gate. A execução real exige termo + escopo + consent,
    exatamente como :func:`execute_scan`.
    """
    goal = Goal.build(goal_kind, targets, perspective=perspective, profile=profile)
    registry = PluginRegistry.discover()

    if dry_run:
        # Preview seguro (nada executa, nada toca a rede): não exige provedor.
        engine = CognitiveEngine(registry, completion=_completion(use_ai))
        planner, decisions = engine.plan_only(goal)
        return PlanOutcome(
            goal=goal,
            planner_name=planner.name,
            ai_used=bool(getattr(planner, "ai_generated", False)),
            decisions=decisions,
        )

    # Execução real: a IA é obrigatória (§3.4/ADR-0012). Sem provedor → recusa
    # acionável antes de qualquer prompt. A IA comanda o scan (AgenticPlanner).
    completion = _require_completion()
    if not accept_terms(assume_yes=assume_yes, input_fn=input_fn, echo=echo):
        raise SessionAborted("Termo de uso não aceito.")
    scope = build_scope(scope_path, targets, goal.perspective)
    try:
        ConsentGate(scope.engagement, targets).require(assume_yes=assume_yes, input_fn=input_fn)
    except ConsentDenied as exc:
        raise SessionAborted(str(exc)) from exc

    feeds = FeedCache.load()
    risk = RiskScorer(feeds, online=online_enrich)
    store = FindingStore(db)
    engine = CognitiveEngine(registry, risk=risk, store=store, completion=completion)
    report = engine.run(goal, scope=scope, override_perspective=override_perspective)
    return PlanOutcome(
        goal=goal,
        planner_name=report.planner_name,
        ai_used=report.ai_used,
        decisions=report.decisions,
        report=report,
        suggestions=report.suggestions,
    )


def _completion(use_ai: bool) -> "CompletionPort | None":
    """Provedor de IA para o preview (dry-run). None se não pedido/indisponível —
    o dry-run é só uma prévia do plano, não uma execução."""
    if not use_ai:
        return None
    from ..ai.provider import default_provider

    return cast("CompletionPort | None", default_provider())


def _require_completion() -> "CompletionPort":
    """Gate AI-native (§3.4/ADR-0012): exige um provedor para executar de verdade.

    Levanta ``AIProviderRequired`` (acionável) se nenhum provedor está configurado.
    Os provedores concretos (`_HTTPProvider`) implementam ``complete`` — a porta
    que a IA usa para comandar o scan."""
    from ..ai.provider import require_provider

    return cast("CompletionPort", require_provider())


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
    # Gate AI-native (§3.4/ADR-0012): sem provedor de IA, o scan é recusado com um
    # erro acionável — antes de qualquer prompt de termo/consent.
    _require_completion()
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
