"""Policy / Guardrail Engine — o freio determinístico da autonomia (ADR-0011).

Fase 0 da plataforma autônoma: **antes** de dar qualquer poder de execução à IA,
existe um motor de política que arbitra cada ação proposta. A IA propõe; a
política dispõe. O Policy Engine é **determinístico e inviolável** — a autonomia
da IA acontece *dentro* de um envelope de autorização/escopo/destrutividade, nunca
fora dele (CLAUDE.md §4).

Toda ação ativa carrega uma :class:`ImpactClass`; o :class:`PolicyEngine` decide,
com motivo logado: **executar / pedir aprovação humana (HITL) / recusar**.
"""

from __future__ import annotations

from .engine import PolicyDecision, PolicyEngine, ProposedAction, Verdict
from .impact import ImpactClass

__all__ = [
    "ImpactClass",
    "PolicyEngine",
    "PolicyDecision",
    "ProposedAction",
    "Verdict",
]
