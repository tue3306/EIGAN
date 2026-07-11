"""CognitiveEngine — o loop goal-driven (ADR-0007).

Amarra os contratos: ``Goal → Planner → [Agent → ToolSelector → Execution] →
Feedback → replan → StopCondition``. Reusa o Capability Registry
(:class:`PluginRegistry`) e a execução segura existente — **não** reimplementa
subprocess nem escopo. Cada decisão vira uma :class:`DecisionEntry` (capacidade,
ferramenta escolhida, motivos, alternativas) — o rastro auditável exigido pelo
§3.4 do CLAUDE.md.

Fronteiras garantidas por código:
* A IA (se houver) só reordenou capacidades no Planner; aqui ela não entra.
* O `ToolSelector` (determinístico) escolheu a ferramenta.
* `SafeExecution` valida escopo por alvo antes de rodar o runner seguro.
* Agente scaffold / capacidade sem ferramenta ⇒ *sugerido, não executado*.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Protocol

from ...findings.dedup import deduplicate
from ...findings.schema import Finding
from ...findings.store import FindingStore
from ...perspective import Perspective
from ...security.scope import Scope, ScopeViolation
from .. import events as ev
from ..cascade import CascadeGraph
from ..events import EventSink, NullSink
from ..plugin import PluginSpec
from ..registry import PluginRegistry
from ..risk import RiskScorer
from .agent import AgentRegistry
from .feedback import Feedback, ScanState, StopCondition, StopReason, Suggestion
from .goal import Goal
from .planner import AgenticPlanner, CompletionPort, DeterministicPlanner, Planner
from .selection import Prefer, SelectionContext, ToolSelector

log = logging.getLogger("eigan.cognitive")

# perfil de scan → o que o Tool Selection Engine prioriza.
_PREFER_BY_PROFILE: dict[str, Prefer] = {
    "quick": Prefer.SPEED,
    "deep": Prefer.ACCURACY,
}


class ExecutionPort(Protocol):
    """Porta de execução — o engine não conhece subprocess, só esta interface."""

    def execute(
        self, spec: PluginSpec, target: str, perspective: Perspective, **opts
    ) -> list[Finding]: ...


@dataclass
class SafeExecution:
    """Execução segura: valida escopo por alvo, então roda o runner do plugin.

    Espelha a política do `Orchestrator` (subprocess com lista de args, nunca
    ``shell=True``). ``ScopeViolation`` sobe para o loop, que a registra como
    *fora de escopo* e segue — nunca derruba o scan."""

    scope: Scope
    override: bool = False

    def execute(
        self, spec: PluginSpec, target: str, perspective: Perspective, **opts
    ) -> list[Finding]:
        self.scope.enforce(target, perspective=perspective, override=self.override)
        findings = spec.scan(target, **opts)
        for f in findings:
            f.perspective = perspective
        return findings


@dataclass
class DecisionEntry:
    """Uma linha do rastro de decisões — tudo logado e justificado."""

    step: int
    capability: str
    agent: str
    action: str  # selected | executed | skipped | failed | suggested | scaffold | stop
    tool: str = ""
    reasons: tuple[str, ...] = ()
    findings: int = 0
    origin: str = ""
    detail: str = ""

    def render(self) -> str:
        head = f"#{self.step} [{self.action}] {self.capability}"
        if self.agent:
            head += f" · agente={self.agent}"
        if self.tool:
            head += f" · {self.tool}"
        if self.findings:
            head += f" · {self.findings} finding(s)"
        if self.reasons:
            head += "  ← " + "; ".join(self.reasons)
        if self.detail:
            head += f"  ({self.detail})"
        return head


@dataclass
class CognitiveReport:
    goal: Goal
    scan_id: Optional[int]
    findings: list[Finding]
    decisions: list[DecisionEntry]
    stop_reason: StopReason
    planner_name: str
    ai_used: bool
    suggestions: list[Suggestion] = field(default_factory=list)


class CognitiveEngine:
    """Orquestrador goal-driven: planeja capacidades, seleciona ferramentas,
    executa com escopo e replaneja pela descoberta — tudo auditável."""

    def __init__(
        self,
        registry: Optional[PluginRegistry] = None,
        *,
        planner: Optional[Planner] = None,
        agents: Optional[AgentRegistry] = None,
        selector: Optional[ToolSelector] = None,
        risk: Optional[RiskScorer] = None,
        store: Optional[FindingStore] = None,
        completion: Optional[CompletionPort] = None,
    ) -> None:
        self._registry = registry if registry is not None else PluginRegistry.discover()
        self._graph = CascadeGraph.from_registry(self._registry)
        self._agents = agents if agents is not None else AgentRegistry.default()
        self._selector = selector if selector is not None else ToolSelector(self._registry)
        self._risk = risk
        self._store = store
        # Planner: AgenticPlanner (IA comanda o plano fim a fim) se houver IA
        # disponível; senão o determinístico (fallback — funciona sem chave).
        base = DeterministicPlanner(self._registry, self._graph)
        if planner is not None:
            self._planner: Planner = planner
        elif completion is not None and completion.available():
            self._planner = AgenticPlanner(base, completion)
        else:
            self._planner = base

    @property
    def planner(self) -> Planner:
        return self._planner

    def plan_only(self, goal: Goal) -> tuple[Planner, list[DecisionEntry]]:
        """Constrói o plano inicial e a seleção **sem executar** (dry-run).

        Não passa pelo consent gate: nada ativo roda. Serve ao comando
        ``plan --dry-run`` para mostrar o Planner escolhendo/justificando."""
        plan = self._planner.initial_plan(goal)
        ctx = self._base_context(goal)
        decisions: list[DecisionEntry] = []
        for i, step in enumerate(plan.steps, start=1):
            agent = self._agents.for_capability(step.capability)
            if agent is None or not agent.built:
                decisions.append(
                    DecisionEntry(
                        step=i,
                        capability=step.capability.value,
                        agent=agent.name if agent else "—",
                        action="scaffold",
                        origin=step.origin,
                        detail="agente não construído (sugerido, não executado)",
                    )
                )
                continue
            choice = self._selector.select(step.capability, ctx)
            if choice is None:
                decisions.append(
                    DecisionEntry(
                        step=i,
                        capability=step.capability.value,
                        agent=agent.name,
                        action="suggested",
                        origin=step.origin,
                        reasons=("nenhuma ferramenta instalada provê esta capacidade",),
                    )
                )
                continue
            decisions.append(
                DecisionEntry(
                    step=i,
                    capability=step.capability.value,
                    agent=agent.name,
                    action="selected",
                    tool=choice.tool,
                    reasons=choice.reasons,
                    origin=step.origin,
                )
            )
        return self._planner, decisions

    def run(
        self,
        goal: Goal,
        *,
        scope: Scope,
        execution: Optional[ExecutionPort] = None,
        override_perspective: bool = False,
        sink: Optional[EventSink] = None,
        **tool_opts,
    ) -> CognitiveReport:
        """Executa o loop cognitivo. O chamador deve ter passado pelo consent gate
        (autorização) antes; aqui o escopo é revalidado por alvo (defesa em
        profundidade)."""
        emitter: EventSink = sink if sink is not None else NullSink()
        exec_port: ExecutionPort = (
            execution
            if execution is not None
            else SafeExecution(scope, override=override_perspective)
        )
        persp = goal.perspective

        scan_id: Optional[int] = None
        if self._store is not None:
            scan_id = self._store.create_scan(
                scope.engagement or goal.kind.value,
                f"{persp.value}/{goal.profile}",
                list(goal.targets),
            )
        emitter.emit(ev.scan_status(scan_id, "running", goal.kind.label))

        plan = self._planner.initial_plan(goal)
        state = ScanState()
        stop = StopCondition(goal.budget)
        decisions: list[DecisionEntry] = []

        # Timeline: registra o raciocínio inicial da IA (ou do determinístico).
        driver = "IA" if getattr(self._planner, "ai_generated", False) else "determinístico"
        plan_entry = DecisionEntry(
            step=0,
            capability="",
            agent="",
            action="planned",
            origin=self._planner.name,
            reasons=tuple(f"{s.capability.value}: {s.reason}" for s in plan.steps),
            detail=f"plano por {driver}: {', '.join(c.value for c in plan.capabilities())}",
        )
        decisions.append(plan_entry)
        emitter.emit(ev.log(plan_entry.render()))
        stop_hint = getattr(self._planner, "stop_hint", "")
        if stop_hint:
            emitter.emit(ev.log(f"#0 [stop-hint] IA sugere encerrar quando: {stop_hint}"))

        base_ctx = self._base_context(goal)
        stop_reason = StopReason.PLAN_EXHAUSTED
        step_no = 0

        while True:
            budget_hit = stop.check(state)
            if budget_hit is not None:
                stop_reason = budget_hit
                break

            step = plan.pop_next()
            if step is None:
                stop_reason = (
                    StopReason.NO_NEW_EVIDENCE if state.findings else StopReason.PLAN_EXHAUSTED
                )
                break

            if step.capability in state.executed_capabilities:
                continue  # já coberta (evita re-execução após replan)

            step_no += 1
            # Timeline de raciocínio: por que esta capacidade está no plano
            # (estratégia | cascata determinística | onda adaptativa da IA).
            emitter.emit(
                ev.log(f"#{step_no} [plano:{step.origin}] {step.capability.value} ← {step.reason}")
            )
            agent = self._agents.for_capability(step.capability)
            if agent is None or not agent.built:
                d = DecisionEntry(
                    step=step_no,
                    capability=step.capability.value,
                    agent=agent.name if agent else "—",
                    action="scaffold",
                    origin=step.origin,
                    detail="agente não construído (sugerido, não executado)",
                )
                decisions.append(d)
                emitter.emit(ev.log(d.render()))
                state.executed_capabilities.add(step.capability)
                continue

            ctx = base_ctx.with_tags(state.context_tags)
            choice = self._selector.select(step.capability, ctx)
            if choice is None:
                d = DecisionEntry(
                    step=step_no,
                    capability=step.capability.value,
                    agent=agent.name,
                    action="suggested",
                    origin=step.origin,
                    reasons=("nenhuma ferramenta instalada provê esta capacidade",),
                )
                decisions.append(d)
                emitter.emit(ev.log(d.render()))
                state.executed_capabilities.add(step.capability)
                continue

            sel = DecisionEntry(
                step=step_no,
                capability=step.capability.value,
                agent=agent.name,
                action="selected",
                tool=choice.tool,
                reasons=choice.reasons,
                origin=step.origin,
            )
            decisions.append(sel)
            emitter.emit(ev.log(sel.render()))

            step_findings, duration = self._execute_step(
                exec_port,
                choice.spec,
                goal,
                persp,
                step_no,
                agent.name,
                decisions,
                emitter,
                tool_opts,
            )
            state.absorb(Feedback(step.capability, choice.tool, step_findings, duration))
            done = DecisionEntry(
                step=step_no,
                capability=step.capability.value,
                agent=agent.name,
                action="executed",
                tool=choice.tool,
                findings=len(step_findings),
                origin=step.origin,
            )
            decisions.append(done)
            emitter.emit(ev.log(done.render()))

            # replan dirigido por descoberta: piso determinístico (cascata) +
            # onda adaptativa da IA. Emite os passos acrescentados (timeline).
            before = set(plan.capabilities())
            self._planner.replan(goal, state, plan)
            for s in plan.steps:
                if s.capability not in before and s.origin in ("cascade", "ai"):
                    emitter.emit(
                        ev.log(f"#{step_no} [replan:{s.origin}] +{s.capability.value} ← {s.reason}")
                    )
            state.mark_replanned()

        return self._finalize(goal, scan_id, state, decisions, stop_reason, emitter)

    # ── auxiliares ────────────────────────────────────────────────────────────
    def _execute_step(
        self,
        exec_port: ExecutionPort,
        spec: PluginSpec,
        goal: Goal,
        persp: Perspective,
        step_no: int,
        agent_name: str,
        decisions: list[DecisionEntry],
        emitter: EventSink,
        tool_opts: dict,
    ) -> tuple[list[Finding], float]:
        findings: list[Finding] = []
        started = time.monotonic()
        for target in goal.targets:
            emitter.emit(ev.tool_execution(spec.name, target, "in_progress"))
            try:
                produced = exec_port.execute(spec, target, persp, **tool_opts)
                findings.extend(produced)
                # streaming em tempo real: cada descoberta vai ao feed do dashboard,
                # já anotada com as ferramentas que ela dispararia (intenção da cascata).
                for f in produced:
                    triggers = [t.tool for t in self._graph.triggered_by(f)]
                    emitter.emit(ev.discovery(f, triggers))
            except ScopeViolation as exc:
                decisions.append(
                    DecisionEntry(
                        step=step_no,
                        capability="",
                        agent=agent_name,
                        action="skipped",
                        tool=spec.name,
                        detail=f"fora de escopo: {exc}",
                    )
                )
                emitter.emit(ev.tool_execution(spec.name, target, "skipped", detail=str(exc)))
            except Exception as exc:  # noqa: BLE001 — um plugin (ToolNotAvailable/erro) não derruba o loop
                decisions.append(
                    DecisionEntry(
                        step=step_no,
                        capability="",
                        agent=agent_name,
                        action="failed",
                        tool=spec.name,
                        detail=str(exc),
                    )
                )
                emitter.emit(ev.tool_execution(spec.name, target, "failed", detail=str(exc)))
            else:
                emitter.emit(ev.tool_execution(spec.name, target, "completed", 100))
        return findings, time.monotonic() - started

    def _finalize(
        self,
        goal: Goal,
        scan_id: Optional[int],
        state: ScanState,
        decisions: list[DecisionEntry],
        stop_reason: StopReason,
        emitter: EventSink,
    ) -> CognitiveReport:
        findings = deduplicate(state.findings)
        if self._risk is not None:
            findings = self._risk.score(findings)
        findings.sort(key=lambda f: (f.risk_rank, f.severity.rank), reverse=True)

        if self._store is not None and scan_id is not None:
            self._store.add_findings(scan_id, findings)
            self._store.finish_scan(scan_id)

        decisions.append(
            DecisionEntry(
                step=state.steps_executed,
                capability="",
                agent="",
                action="stop",
                detail=stop_reason.value,
            )
        )
        emitter.emit(
            ev.analysis_complete(
                {
                    "findings": len(findings),
                    "capabilities": state.steps_executed,
                    "suggestions": len(state.suggestions),
                    "stop": stop_reason.value,
                }
            )
        )
        emitter.emit(ev.scan_status(scan_id, "completed"))
        return CognitiveReport(
            goal=goal,
            scan_id=scan_id,
            findings=findings,
            decisions=decisions,
            stop_reason=stop_reason,
            planner_name=self._planner.name,
            ai_used=bool(getattr(self._planner, "ai_generated", False)),
            suggestions=list(state.suggestions),
        )

    def _base_context(self, goal: Goal) -> SelectionContext:
        prefer = _PREFER_BY_PROFILE.get(goal.profile, Prefer.BALANCED)
        return SelectionContext(
            perspective=goal.perspective,
            tags=frozenset({goal.perspective.value}),
            prefer=prefer,
        )
