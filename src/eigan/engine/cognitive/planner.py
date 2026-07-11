"""Planner — traduz um :class:`Goal` em capacidades e replaneja por feedback.

Fronteira do CLAUDE.md (§3.3) explícita: o Planner decide **capacidades**, nunca
ferramentas nem comandos. Duas implementações plugáveis (ADR-0007):

* :class:`DeterministicPlanner` — estratégia declarada por objetivo + replan pela
  cascata determinística (:class:`CascadeGraph`). É o **fallback**: funciona sem
  qualquer chave de IA.
* :class:`AIPlanner` — usa a IA apenas para **reordenar** capacidades válidas
  (grounding na lista do enum; ids inventados são descartados — anti-invenção).
  Em qualquer erro/instabilidade, cai para o determinístico.

O `TYPE_CHECKING`/Protocols mantêm a dependência apontando para dentro (o Planner
consome portas, não a infra concreta).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from ...capability import Capability
from ...perspective import Perspective
from ..pipeline import stages_for
from .goal import Goal

if TYPE_CHECKING:
    from ..cascade import CascadeGraph
    from ..plugin import PluginSpec
    from .feedback import ScanState

log = logging.getLogger("eigan.cognitive.planner")


@dataclass(frozen=True)
class PlanStep:
    """Uma capacidade a executar + de onde veio a decisão (auditável)."""

    capability: Capability
    reason: str
    origin: str  # "strategy" | "cascade" | "ai"


@dataclass
class Plan:
    """Fila de capacidades a executar. O engine consome pela frente; o replan
    acrescenta ao fim. Determinístico e inspecionável."""

    steps: list[PlanStep] = field(default_factory=list)

    def pop_next(self) -> PlanStep | None:
        return self.steps.pop(0) if self.steps else None

    def add(self, step: PlanStep) -> None:
        self.steps.append(step)

    def has(self, capability: Capability) -> bool:
        return any(s.capability == capability for s in self.steps)

    def capabilities(self) -> list[Capability]:
        return [s.capability for s in self.steps]

    def __len__(self) -> int:
        return len(self.steps)

    def __bool__(self) -> bool:
        return bool(self.steps)


@runtime_checkable
class Planner(Protocol):
    """Contrato do Planner (ADR-0007)."""

    name: str
    ai_generated: bool

    def initial_plan(self, goal: Goal) -> Plan: ...

    def replan(self, goal: Goal, state: "ScanState", plan: Plan) -> Plan: ...


class PlanRegistryPort(Protocol):
    """Porta que o Planner consome do Capability Registry (`PluginRegistry`)."""

    def capabilities(self) -> set[Capability]: ...

    def get(self, name: str) -> "PluginSpec | None": ...


def _canonical_order(perspective: Perspective) -> dict[Capability, int]:
    """Índice de ordem canônica das capacidades segundo o pipeline da perspectiva.

    Reusa a fonte declarativa (`engine/pipeline.py`), então planner e pipeline
    nunca divergem. Capacidades fora do pipeline recebem ordem alta (vão ao fim).
    """
    order: dict[Capability, int] = {}
    i = 0
    for stage in stages_for(perspective, "standard"):
        for cap in stage.capabilities:
            order.setdefault(cap, i)
            i += 1
    return order


@dataclass
class DeterministicPlanner:
    """Plano = estratégia do objetivo (ordenada pelo pipeline). Replan = cascata."""

    registry: PlanRegistryPort
    graph: "CascadeGraph"
    name: str = "deterministic"
    ai_generated: bool = False

    def initial_plan(self, goal: Goal) -> Plan:
        order = _canonical_order(goal.perspective)
        # ordena a estratégia pela ordem canônica do pipeline (estável).
        caps = sorted(goal.strategy, key=lambda c: (order.get(c, 10_000), c.value))
        provided = self.registry.capabilities()
        steps: list[PlanStep] = []
        for cap in caps:
            scaffold = cap not in provided
            reason = f"estratégia de «{goal.kind.label}»"
            if scaffold:
                reason += " — sem plugin (sugerido, não executado)"
            steps.append(PlanStep(capability=cap, reason=reason, origin="strategy"))
        return Plan(steps=steps)

    def replan(self, goal: Goal, state: "ScanState", plan: Plan) -> Plan:
        """Descoberta nova → capacidades adicionais via cascata (determinístico).

        Cada disparo da cascata aponta uma *ferramenta*; mapeamos de volta às
        **capacidades** do plugin que a provê (a IA nunca vê ferramenta aqui).
        Ferramentas sugeridas mas não registradas/roadmap são anotadas como
        *sugeridas, não executadas* — nunca fingem rodar."""
        for trig in self.graph.triggered_by_all(state.new_findings):
            spec = self.registry.get(trig.tool)
            if spec is None:
                state.note_suggestion(trig.tool, trig.reason)
                continue
            for cap in spec.metadata.capabilities:
                if cap in state.executed_capabilities or plan.has(cap):
                    continue
                plan.add(
                    PlanStep(
                        capability=cap,
                        reason=f"cascata: {trig.reason} (via {trig.tool})",
                        origin="cascade",
                    )
                )
        return plan


class CompletionPort(Protocol):
    """Porta mínima de IA para o Planner (satisfeita pelos provedores HTTP)."""

    def available(self) -> bool: ...

    def complete(self, system: str, user: str) -> str: ...


_AI_SYSTEM = (
    "Você prioriza CAPACIDADES de segurança para um objetivo. Regras rígidas: "
    "responda APENAS com ids da lista fornecida, um por linha, em ordem de "
    "prioridade. NUNCA invente ids, ferramentas, comandos, CVE, versões ou scores. "
    "Você não escolhe ferramentas nem executa nada — só ordena capacidades."
)


@dataclass
class AIPlanner:
    """Reordena as capacidades do plano determinístico usando a IA (com fallback).

    A IA só decide **ordem** entre capacidades já válidas — não introduz nada. O
    replan permanece determinístico (cascata), mantendo o loop seguro e auditável.
    """

    base: DeterministicPlanner
    completion: CompletionPort
    name: str = "ai"
    ai_generated: bool = True

    def initial_plan(self, goal: Goal) -> Plan:
        plan = self.base.initial_plan(goal)
        if not self.completion.available() or not plan.steps:
            self.ai_generated = False  # caiu no determinístico
            return plan
        ordered = self._reorder(goal, [s.capability for s in plan.steps])
        if ordered is None:
            self.ai_generated = False
            return plan
        by_cap = {s.capability: s for s in plan.steps}
        steps = [
            PlanStep(
                capability=c,
                reason=f"priorizado pela IA · {by_cap[c].reason}",
                origin="ai",
            )
            for c in ordered
        ]
        return Plan(steps=steps)

    def replan(self, goal: Goal, state: "ScanState", plan: Plan) -> Plan:
        # replan é determinístico (cascata) por design — a IA não decide execução.
        return self.base.replan(goal, state, plan)

    def _reorder(self, goal: Goal, caps: list[Capability]) -> list[Capability] | None:
        allowed = {c.value: c for c in caps}
        user = (
            f"Objetivo: {goal.kind.label}\n"
            f"Capacidades disponíveis (use SOMENTE estes ids):\n"
            + "\n".join(f"- {v}" for v in allowed)
            + "\n\nResponda os ids em ordem de prioridade, um por linha."
        )
        try:
            raw = self.completion.complete(_AI_SYSTEM, user)
        except Exception as exc:  # noqa: BLE001 — IA instável nunca derruba o plano
            log.warning("AIPlanner: fallback determinístico (%s)", exc)
            return None
        picked: list[Capability] = []
        seen: set[Capability] = set()
        for line in raw.splitlines():
            tok = line.strip().strip("-*•0123456789.) ").lower()
            cap = allowed.get(tok)
            if cap is not None and cap not in seen:  # ids inventados são ignorados
                seen.add(cap)
                picked.append(cap)
        # nada é perdido: capacidades não citadas mantêm a ordem determinística.
        for c in caps:
            if c not in seen:
                picked.append(c)
        return picked or None
