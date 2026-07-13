"""Policy-as-code: o Guardrail Engine é o freio determinístico da autonomia.

Estes testes são a **pré-condição** de qualquer poder dado à IA (ADR-0011): a
política recusa fora de escopo, exige HITL em exploit, proíbe STATE_CHANGING e
libera só o que está dentro do escopo e do teto de destrutividade.
"""

from __future__ import annotations

from eigan.perspective import Perspective
from eigan.policy import ImpactClass, PolicyEngine, ProposedAction, Verdict
from eigan.policy.engine import ceiling_for_profile
from eigan.security.scope import Scope

P = Perspective
IC = ImpactClass


def _engine(**kw) -> PolicyEngine:
    # Trava dura (opt-in) para exercitar a recusa de alvo fora de escopo: no modo
    # efêmero (default) a autorização é o consent gate e não há bloqueio por lista.
    scope = Scope(
        authorized=True, hosts=["example.com"], perspective=P.EXTERNAL, enforce_membership=True
    )
    return PolicyEngine(scope=scope, perspective=P.EXTERNAL, **kw)


def _action(target="example.com", impact=IC.ACTIVE_SAFE, tool="naabu") -> ProposedAction:
    return ProposedAction(
        tool=tool, target=target, capability="port_discovery", impact_class=impact
    )


def test_passive_and_active_safe_run_autonomously_in_scope():
    eng = _engine()
    for ic in (IC.PASSIVE, IC.ACTIVE_SAFE):
        d = eng.vet(_action(impact=ic))
        assert d.verdict is Verdict.EXECUTE
        assert d.allowed is True


def test_out_of_scope_is_rejected():
    eng = _engine()
    d = eng.vet(_action(target="attacker-controlled.example.net"))
    assert d.verdict is Verdict.REJECT
    assert "escopo" in d.reason.lower()


def test_intrusive_needs_human_approval_by_default():
    eng = _engine()  # teto padrão = active_safe
    d = eng.vet(_action(impact=IC.ACTIVE_INTRUSIVE, tool="ffuf"))
    assert d.verdict is Verdict.NEEDS_APPROVAL


def test_intrusive_autonomous_when_profile_raises_ceiling():
    eng = _engine(auto_approve_ceiling=ceiling_for_profile("aggressive"))
    d = eng.vet(_action(impact=IC.ACTIVE_INTRUSIVE, tool="ffuf"))
    assert d.verdict is Verdict.EXECUTE


def test_exploit_rejected_without_flag():
    eng = _engine()  # allow_exploit=False
    d = eng.vet(_action(impact=IC.EXPLOIT_VALIDATION, tool="metasploit"))
    assert d.verdict is Verdict.REJECT
    assert "allow-exploit" in d.reason


def test_exploit_needs_hitl_even_with_flag():
    eng = _engine(allow_exploit=True)
    d = eng.vet(_action(impact=IC.EXPLOIT_VALIDATION, tool="metasploit"))
    assert d.verdict is Verdict.NEEDS_APPROVAL  # nunca autônomo, mesmo autorizado


def test_state_changing_is_forbidden_by_default():
    eng = _engine(allow_exploit=True, auto_approve_ceiling=IC.STATE_CHANGING)
    d = eng.vet(_action(impact=IC.STATE_CHANGING, tool="ansible"))
    assert d.verdict is Verdict.REJECT  # proibido mesmo com teto no máximo


def test_scope_beats_everything_even_state_changing_check():
    # ordem: escopo é verificado ANTES da classe — alvo fora recusa por escopo.
    eng = _engine(allow_exploit=True)
    d = eng.vet(_action(target="10.0.0.9", impact=IC.EXPLOIT_VALIDATION))
    # 10.0.0.9 é privado sob perspectiva external → recusado por escopo/perspectiva.
    assert d.verdict is Verdict.REJECT
    assert "escopo" in d.reason.lower()


def test_impact_class_from_str_falls_back():
    assert ImpactClass.from_str("passive", default=IC.ACTIVE_SAFE) is IC.PASSIVE
    assert ImpactClass.from_str("inexistente", default=IC.ACTIVE_SAFE) is IC.ACTIVE_SAFE
    assert ImpactClass.from_str(None, default=IC.ACTIVE_SAFE) is IC.ACTIVE_SAFE


def test_decision_render_is_auditable():
    d = _engine().vet(_action())
    text = d.render()
    assert "naabu" in text and "example.com" in text and "execute" in text
