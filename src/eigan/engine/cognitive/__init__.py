"""Núcleo cognitivo goal-driven (ADR-0007).

Camada acima do `Orchestrator`: traduz um :class:`Goal` em capacidades
(:class:`Planner`), escolhe a ferramenta de cada capacidade
(:class:`ToolSelector`), roteia por especialidade (:class:`Agent`), executa com
escopo e replaneja pela descoberta — tudo determinístico e auditável, com a IA
restrita a *ordenar capacidades* (fallback determinístico sempre presente).
"""

from __future__ import annotations

from .agent import Agent, AgentRegistry, default_agents
from .engine import (
    CognitiveEngine,
    CognitiveReport,
    DecisionEntry,
    ExecutionPort,
    SafeExecution,
)
from .feedback import Feedback, ScanState, StopCondition, StopReason, Suggestion
from .goal import Budget, Goal, GoalKind
from .planner import (
    AgenticPlanner,
    AIPlanner,
    CompletionPort,
    DeterministicPlanner,
    Plan,
    Planner,
    PlanStep,
)
from .selection import (
    Prefer,
    Rating,
    SelectionContext,
    SelectionSignals,
    ToolChoice,
    ToolSelector,
)

__all__ = [
    "Agent",
    "AgentRegistry",
    "default_agents",
    "CognitiveEngine",
    "CognitiveReport",
    "DecisionEntry",
    "ExecutionPort",
    "SafeExecution",
    "Feedback",
    "ScanState",
    "StopCondition",
    "StopReason",
    "Suggestion",
    "Budget",
    "Goal",
    "GoalKind",
    "AgenticPlanner",
    "AIPlanner",
    "CompletionPort",
    "DeterministicPlanner",
    "Plan",
    "Planner",
    "PlanStep",
    "Prefer",
    "Rating",
    "SelectionContext",
    "SelectionSignals",
    "ToolChoice",
    "ToolSelector",
]
