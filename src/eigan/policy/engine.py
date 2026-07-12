"""PolicyEngine — arbitra cada ação proposta pela IA (determinístico, ADR-0011).

Invariante mestre-alvo (CLAUDE.md §2/§4): **nenhuma ação ativa deve tocar a rede
sem passar por aqui**. A IA propõe uma :class:`ProposedAction`; o motor devolve um
:class:`Verdict` — EXECUTE / NEEDS_APPROVAL (HITL) / REJECT — com motivo logado.
Nada nisto depende de IA: é política pura, testável como *policy-as-code*.

Estado (ADR-0011, honesto §3.6): a **trava dura de escopo/autorização** (passo 1
de :meth:`_decide`, via :meth:`Scope.enforce`) já roda em todo o caminho de
execução; submeter cada tool-call ao :meth:`vet` completo (arbitragem por
``ImpactClass``) é a **Fase 3** do roadmap — ainda não está no caminho quente.

Ordem de decisão (a primeira que casar vence):

1. **Escopo/autorização** (trava dura): alvo fora do escopo autorizado ⇒ REJECT.
2. **STATE_CHANGING**: proibido por padrão (nunca altera terceiros) ⇒ REJECT.
3. **EXPLOIT_VALIDATION**: exige a flag ``allow_exploit`` **e** aprovação humana.
4. **Acima do teto autônomo do perfil** (ex.: intrusiva) ⇒ NEEDS_APPROVAL.
5. Caso contrário ⇒ EXECUTE (passiva/ativa-segura dentro do escopo).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

from ..perspective import Perspective
from ..security.scope import Scope, ScopeViolation
from .impact import ImpactClass

log = logging.getLogger("eigan.policy")


class Verdict(str, Enum):
    EXECUTE = "execute"  # autônomo: pode rodar já
    NEEDS_APPROVAL = "needs_approval"  # HITL: espera um aprovador humano
    REJECT = "reject"  # recusado (motivo logado); nunca roda


@dataclass(frozen=True)
class ProposedAction:
    """Uma ação que a IA (ou a cascata) quer executar — antes do vetting."""

    tool: str
    target: str
    capability: str
    impact_class: ImpactClass
    justification: str = ""


@dataclass(frozen=True)
class PolicyDecision:
    """Resultado do vetting — auditável (proposta → veredito → motivo)."""

    verdict: Verdict
    reason: str
    action: ProposedAction

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.EXECUTE

    def render(self) -> str:
        return (
            f"[{self.verdict.value}] {self.action.tool} → {self.action.target} "
            f"({self.action.impact_class.value}) ← {self.reason}"
        )


@dataclass
class PolicyEngine:
    """Motor determinístico de política. Uma instância por run/engajamento.

    ``auto_approve_ceiling`` é o teto de destrutividade que roda **sem** humano
    (padrão: ativa-segura). ``allow_exploit`` habilita — só então — a *classe*
    EXPLOIT_VALIDATION, que ainda exige aprovação humana."""

    scope: Scope
    perspective: Perspective
    allow_exploit: bool = False
    auto_approve_ceiling: ImpactClass = ImpactClass.ACTIVE_SAFE
    override_perspective: bool = False

    def vet(self, action: ProposedAction) -> PolicyDecision:
        decision = self._decide(action)
        log.info("policy: %s", decision.render())
        return decision

    def _decide(self, action: ProposedAction) -> PolicyDecision:
        # 1. Escopo/autorização — trava dura, sempre primeiro (defesa em profundidade).
        try:
            self.scope.enforce(
                action.target,
                perspective=self.perspective,
                override=self.override_perspective,
            )
        except ScopeViolation as exc:
            return self._reject(action, f"fora de escopo/autorização: {exc}")

        # 2. STATE_CHANGING é proibido por padrão (nunca altera terceiros).
        if action.impact_class is ImpactClass.STATE_CHANGING:
            return self._reject(
                action,
                "classe STATE_CHANGING é proibida por padrão (não altera o alvo de terceiros)",
            )

        # 3. Validação de exploração: exige flag explícita + aprovação humana.
        if action.impact_class is ImpactClass.EXPLOIT_VALIDATION:
            if not self.allow_exploit:
                return self._reject(
                    action, "validação de exploração exige --allow-exploit (desabilitado)"
                )
            return self._hitl(
                action, "validação de exploração exige aprovação humana (HITL obrigatório)"
            )

        # 4. Acima do teto autônomo do perfil ⇒ aprovação humana.
        if action.impact_class.rank > self.auto_approve_ceiling.rank:
            return self._hitl(
                action,
                f"{action.impact_class.label} acima do teto autônomo "
                f"({self.auto_approve_ceiling.label}) — requer aprovação",
            )

        # 5. Dentro do escopo e do teto de destrutividade ⇒ autônomo.
        return PolicyDecision(
            Verdict.EXECUTE,
            f"{action.impact_class.label} dentro do escopo e do teto autônomo",
            action,
        )

    @staticmethod
    def _reject(action: ProposedAction, reason: str) -> PolicyDecision:
        return PolicyDecision(Verdict.REJECT, reason, action)

    @staticmethod
    def _hitl(action: ProposedAction, reason: str) -> PolicyDecision:
        return PolicyDecision(Verdict.NEEDS_APPROVAL, reason, action)


# Teto autônomo por perfil de scan. Perfis mais agressivos elevam o teto, mas
# exploit/state-changing continuam gated independentemente do perfil.
CEILING_BY_PROFILE: dict[str, ImpactClass] = {
    "quick": ImpactClass.ACTIVE_SAFE,
    "standard": ImpactClass.ACTIVE_SAFE,
    "deep": ImpactClass.ACTIVE_SAFE,
    "aggressive": ImpactClass.ACTIVE_INTRUSIVE,  # ainda exige HITL p/ exploit+
}


def ceiling_for_profile(profile: str) -> ImpactClass:
    return CEILING_BY_PROFILE.get(profile.strip().lower(), ImpactClass.ACTIVE_SAFE)
