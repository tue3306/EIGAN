"""Testes do núcleo cognitivo (ADR-0007): seleção, planner, agentes, loop.

Cobre a fronteira inegociável: a IA só ordena capacidades (fallback
determinístico); o Tool Selection Engine escolhe a ferramenta de forma pura e
justificada; o Execution Engine executa com escopo; agentes scaffold e
capacidades sem ferramenta viram *sugerido, não executado*.
"""

from __future__ import annotations

import pytest

from eigan.capability import Capability, Category
from eigan.engine.base import BaseToolPlugin
from eigan.engine.cascade import CascadeGraph, CascadeRule
from eigan.engine.cognitive import (
    AgenticPlanner,
    AIPlanner,
    Budget,
    CognitiveEngine,
    DeterministicPlanner,
    Goal,
    GoalKind,
    Plan,
    Prefer,
    SafeExecution,
    ScanState,
    SelectionContext,
    StopCondition,
    StopReason,
    ToolSelector,
)
from eigan.engine.plugin import PluginMetadata, PluginSpec
from eigan.engine.registry import PluginRegistry
from eigan.findings.schema import Finding, Severity
from eigan.perspective import Perspective
from eigan.security.onboarding import build_scope
from eigan.security.scope import Scope


def _hard_scope(*hosts: str, perspective=None) -> Scope:
    """Escopo com trava dura (opt-in): exige pertencimento à lista. Usado onde o
    teste verifica o BLOQUEIO de alvo fora de escopo — no modo efêmero (default) a
    autorização é o consent gate e não há bloqueio por lista."""
    from eigan.perspective import Perspective as _P

    return Scope(
        authorized=True,
        hosts=list(hosts),
        perspective=perspective or _P.EXTERNAL,
        enforce_membership=True,
    )

C = Capability
P = Perspective


# --------------------------------------------------------------------------- #
# Helpers: plugins/registry falsos (sem subprocess).
# --------------------------------------------------------------------------- #
class _FakeRunner(BaseToolPlugin):
    def __init__(self, tool: str, findings: list[Finding], available: bool = True) -> None:
        self.name = tool
        self.binary = tool
        self._findings = findings
        self._available = available

    def available(self) -> bool:
        return self._available

    def build_args(self, target: str, **options) -> list[str]:
        return []

    def parse(self, result, target) -> list[Finding]:
        return []

    def scan(self, target: str, **options) -> list[Finding]:
        # devolve cópias para não compartilhar estado entre alvos.
        return [
            Finding(
                title=f.title,
                severity=f.severity,
                affected_asset=f.affected_asset,
                source_tool=f.source_tool,
            )
            for f in self._findings
        ]


def _finding(title: str, asset: str, tool: str, sev: Severity = Severity.INFO) -> Finding:
    return Finding(title=title, severity=sev, affected_asset=asset, source_tool=tool)


def _spec(
    name: str,
    caps: tuple[Capability, ...],
    *,
    tool: str | None = None,
    perspectives: tuple[Perspective, ...] = (P.EXTERNAL, P.INTERNAL),
    findings: list[Finding] | None = None,
    available: bool = True,
    speed: str = "medium",
    accuracy: str = "medium",
    resource: str = "medium",
    preferred: tuple[str, ...] = (),
    avoid: tuple[str, ...] = (),
    triggers: tuple[CascadeRule, ...] = (),
) -> PluginSpec:
    meta = PluginMetadata(
        name=name,
        category=Category.RED,
        capabilities=caps,
        supported_perspectives=perspectives,
        tool=tool or name,
        sel_speed=speed,
        sel_accuracy=accuracy,
        sel_resource=resource,
        sel_preferred_when=preferred,
        sel_avoid_when=avoid,
        triggers_on=triggers,
    )
    runner = _FakeRunner(tool or name, findings or [], available)
    return PluginSpec(metadata=meta, runner=runner)


class _FakeCompletion:
    def __init__(self, text: str = "", *, available: bool = True, raises: bool = False) -> None:
        self._text = text
        self._available = available
        self._raises = raises

    def available(self) -> bool:
        return self._available

    def complete(self, system: str, user: str) -> str:
        if self._raises:
            raise RuntimeError("provedor instável")
        return self._text


# --------------------------------------------------------------------------- #
# Tool Selection Engine
# --------------------------------------------------------------------------- #
def _port_registry() -> PluginRegistry:
    naabu = _spec(
        "naabu", (C.PORT_DISCOVERY,), speed="high", resource="low", preferred=("external",)
    )
    nmap = _spec(
        "nmap",
        (C.PORT_DISCOVERY, C.SERVICE_DETECTION),
        accuracy="high",
        preferred=("internal",),
    )
    return PluginRegistry([naabu, nmap])


def test_selector_prefers_fast_tool_external():
    sel = ToolSelector(_port_registry())
    ctx = SelectionContext(
        perspective=P.EXTERNAL, tags=frozenset({"external"}), prefer=Prefer.BALANCED
    )
    choice = sel.select(C.PORT_DISCOVERY, ctx)
    assert choice is not None
    assert choice.tool == "naabu"
    assert choice.reasons  # justificado, nunca caixa-preta
    assert "nmap" in choice.alternatives


def test_selector_prefers_accurate_tool_internal():
    sel = ToolSelector(_port_registry())
    ctx = SelectionContext(
        perspective=P.INTERNAL, tags=frozenset({"internal"}), prefer=Prefer.ACCURACY
    )
    choice = sel.select(C.PORT_DISCOVERY, ctx)
    assert choice is not None
    # mesma capability, contexto diferente → ferramenta diferente (escolha não fixa).
    assert choice.tool == "nmap"


def test_selector_avoid_when_excludes_candidate():
    fast = _spec("fast", (C.WEB_CRAWL,), speed="high", avoid=("low_bandwidth",))
    steady = _spec("steady", (C.WEB_CRAWL,), speed="medium")
    sel = ToolSelector(PluginRegistry([fast, steady]))
    ctx = SelectionContext(perspective=P.EXTERNAL, tags=frozenset({"low_bandwidth"}))
    choice = sel.select(C.WEB_CRAWL, ctx)
    assert choice is not None
    assert choice.tool == "steady"


def test_selector_returns_none_when_no_tool_available():
    offline = _spec("offline", (C.PORT_DISCOVERY,), available=False)
    sel = ToolSelector(PluginRegistry([offline]))
    ctx = SelectionContext(perspective=P.EXTERNAL)
    assert sel.select(C.PORT_DISCOVERY, ctx) is None


# --------------------------------------------------------------------------- #
# DeterministicPlanner
# --------------------------------------------------------------------------- #
def _recon_registry(**extra) -> PluginRegistry:
    specs = [
        _spec("subfinder", (C.SUBDOMAIN_ENUMERATION,), perspectives=(P.EXTERNAL,)),
        _spec("naabu", (C.PORT_DISCOVERY,), speed="high", preferred=("external",)),
        _spec("nmap", (C.PORT_DISCOVERY, C.SERVICE_DETECTION), accuracy="high"),
    ]
    specs.extend(extra.get("more", []))
    return PluginRegistry(specs)


def test_deterministic_plan_orders_and_marks_scaffold():
    reg = _recon_registry()
    planner = DeterministicPlanner(reg, CascadeGraph.from_registry(reg))
    goal = Goal.build(GoalKind.ATTACK_SURFACE, ["example.com"])
    plan = planner.initial_plan(goal)
    caps = plan.capabilities()
    # ordem canônica do pipeline: subdomínio antes de portas.
    assert caps.index(C.SUBDOMAIN_ENUMERATION) < caps.index(C.PORT_DISCOVERY)
    # capacidade sem plugin (ex.: web_probe) entra como scaffold honesto.
    web = next(s for s in plan.steps if s.capability == C.WEB_PROBE)
    assert "sugerido" in web.reason


def test_deterministic_replan_adds_capability_from_cascade():
    rule = CascadeRule(execute=("webx",), port=(80,), reason="porta web")
    naabu = _spec("naabu", (C.PORT_DISCOVERY,), triggers=(rule,))
    webx = _spec("webx", (C.WEB_PROBE,))
    reg = PluginRegistry([naabu, webx])
    planner = DeterministicPlanner(reg, CascadeGraph.from_registry(reg))
    goal = Goal.build(GoalKind.EXTERNAL_EXPOSURE, ["h"])
    state = ScanState(new_findings=[_finding("Porta aberta 80/tcp (http)", "h:80", "naabu")])
    plan = Plan([])
    planner.replan(goal, state, plan)
    assert C.WEB_PROBE in plan.capabilities()
    assert plan.steps[0].origin == "cascade"


def test_deterministic_replan_unregistered_tool_becomes_suggestion():
    rule = CascadeRule(execute=("enum4linux",), port=(445,), reason="SMB exposto")
    naabu = _spec("naabu", (C.PORT_DISCOVERY,), triggers=(rule,))
    reg = PluginRegistry([naabu])  # enum4linux NÃO existe
    planner = DeterministicPlanner(reg, CascadeGraph.from_registry(reg))
    goal = Goal.build(GoalKind.EXTERNAL_EXPOSURE, ["h"])
    state = ScanState(
        new_findings=[_finding("Porta aberta 445/tcp (microsoft-ds)", "h:445", "naabu")]
    )
    planner.replan(goal, state, Plan([]))
    assert any(s.tool == "enum4linux" for s in state.suggestions)


# --------------------------------------------------------------------------- #
# AIPlanner — só reordena capacidades válidas; fallback sempre presente
# --------------------------------------------------------------------------- #
def _ai_base() -> DeterministicPlanner:
    reg = PluginRegistry(
        [
            _spec("subfinder", (C.SUBDOMAIN_ENUMERATION,), perspectives=(P.EXTERNAL,)),
            _spec("naabu", (C.PORT_DISCOVERY,)),
        ]
    )
    return DeterministicPlanner(reg, CascadeGraph.from_registry(reg))


def test_ai_planner_reorders_and_drops_invented_ids():
    # a IA prioriza port_discovery e cita um id inventado (deve ser ignorado).
    comp = _FakeCompletion("port_discovery\nnao_existe_xyz\nsubdomain_enumeration")
    planner = AIPlanner(_ai_base(), comp)
    goal = Goal.build(GoalKind.ATTACK_SURFACE, ["example.com"])
    plan = planner.initial_plan(goal)
    caps = plan.capabilities()
    assert caps[0] == C.PORT_DISCOVERY  # reordenado pela IA
    assert C.SUBDOMAIN_ENUMERATION in caps  # nada perdido
    assert planner.ai_generated is True
    assert all(s.origin == "ai" for s in plan.steps)


def test_ai_planner_falls_back_on_error():
    planner = AIPlanner(_ai_base(), _FakeCompletion(raises=True))
    plan = planner.initial_plan(Goal.build(GoalKind.ATTACK_SURFACE, ["h"]))
    assert plan.capabilities()  # plano determinístico intacto
    assert planner.ai_generated is False


def test_ai_planner_falls_back_when_unavailable():
    planner = AIPlanner(_ai_base(), _FakeCompletion(available=False))
    plan = planner.initial_plan(Goal.build(GoalKind.ATTACK_SURFACE, ["h"]))
    assert plan.capabilities()
    assert planner.ai_generated is False


# --------------------------------------------------------------------------- #
# AgenticPlanner — a IA comanda o plano fim a fim (EIGAN v1.0, ADR-0009)
# --------------------------------------------------------------------------- #
def _agentic_registry() -> PluginRegistry:
    return PluginRegistry(
        [
            _spec("subfinder", (C.SUBDOMAIN_ENUMERATION,), perspectives=(P.EXTERNAL,)),
            _spec("naabu", (C.PORT_DISCOVERY,), speed="high", preferred=("external",)),
            _spec("webx", (C.WEB_PROBE,)),
            _spec("nucleix", (C.VULN_TEMPLATE_SCAN,)),
        ]
    )


def _agentic_base() -> DeterministicPlanner:
    reg = _agentic_registry()
    return DeterministicPlanner(reg, CascadeGraph.from_registry(reg))


def test_agentic_planner_plans_initial_from_ai():
    # IA propõe ordem (JSON estruturado) e uma condição de parada.
    comp = _FakeCompletion(
        '{"plan": ["port_discovery", "subdomain_enumeration"], '
        '"stop_when": "quando não houver nova evidência"}'
    )
    planner = AgenticPlanner(_agentic_base(), comp)
    plan = planner.initial_plan(Goal.build(GoalKind.ATTACK_SURFACE, ["example.com"]))
    caps = plan.capabilities()
    assert caps[0] == C.PORT_DISCOVERY  # a IA planejou a ordem
    assert C.SUBDOMAIN_ENUMERATION in caps
    assert planner.ai_generated is True
    assert planner.stop_hint  # a IA sugeriu quando parar (registrado na timeline)
    assert all(s.origin == "ai" for s in plan.steps if s.capability in caps[:2])


def test_agentic_planner_grounds_invented_ids():
    # id inventado pela IA é descartado; a cobertura da estratégia é preservada.
    comp = _FakeCompletion('{"plan": ["port_discovery", "capacidade_inventada_zzz"]}')
    planner = AgenticPlanner(_agentic_base(), comp)
    plan = planner.initial_plan(Goal.build(GoalKind.ATTACK_SURFACE, ["example.com"]))
    ids = [c.value for c in plan.capabilities()]
    assert "capacidade_inventada_zzz" not in ids  # grounding: fora do registry → fora
    assert "port_discovery" in ids


def test_agentic_planner_falls_back_on_non_json():
    planner = AgenticPlanner(_agentic_base(), _FakeCompletion("desculpe, não sei responder"))
    plan = planner.initial_plan(Goal.build(GoalKind.ATTACK_SURFACE, ["h"]))
    assert plan.capabilities()  # plano determinístico intacto
    assert planner.ai_generated is False


def test_agentic_planner_falls_back_on_error():
    planner = AgenticPlanner(_agentic_base(), _FakeCompletion(raises=True))
    plan = planner.initial_plan(Goal.build(GoalKind.ATTACK_SURFACE, ["h"]))
    assert plan.capabilities()
    assert planner.ai_generated is False


def test_agentic_replan_adds_capability_from_ai():
    # a IA lê a descoberta (tag de contexto http) e propõe a próxima onda.
    comp = _FakeCompletion(
        '{"next": [{"capability": "web_probe", "reason": "porta http aberta"}, '
        '{"capability": "id_inventado", "reason": "x"}]}'
    )
    planner = AgenticPlanner(_agentic_base(), comp)
    goal = Goal.build(GoalKind.EXTERNAL_EXPOSURE, ["h"])
    state = ScanState(new_findings=[_finding("Porta aberta 80/tcp (http)", "h:80", "naabu")])
    state.context_tags |= {"http"}
    plan = Plan([])
    planner.replan(goal, state, plan)
    caps = plan.capabilities()
    assert C.WEB_PROBE in caps  # onda adaptativa proposta pela IA
    assert C.VULN_TEMPLATE_SCAN not in caps  # a IA não pediu essa
    assert not any(s.reason for s in plan.steps if "id_inventado" in s.reason)  # grounding
    assert any(s.origin == "ai" for s in plan.steps)


def test_agentic_replan_keeps_deterministic_floor():
    # mesmo com a IA em silêncio, a cascata determinística (piso) roda.
    rule = CascadeRule(execute=("webx",), port=(80,), reason="porta web")
    reg = PluginRegistry(
        [_spec("naabu", (C.PORT_DISCOVERY,), triggers=(rule,)), _spec("webx", (C.WEB_PROBE,))]
    )
    base = DeterministicPlanner(reg, CascadeGraph.from_registry(reg))
    planner = AgenticPlanner(base, _FakeCompletion('{"next": []}'))
    goal = Goal.build(GoalKind.EXTERNAL_EXPOSURE, ["h"])
    state = ScanState(new_findings=[_finding("Porta aberta 80/tcp (http)", "h:80", "naabu")])
    plan = Plan([])
    planner.replan(goal, state, plan)
    web = next(s for s in plan.steps if s.capability == C.WEB_PROBE)
    assert web.origin == "cascade"  # piso determinístico, independente da IA


# --------------------------------------------------------------------------- #
# StopCondition
# --------------------------------------------------------------------------- #
def test_stop_condition_budget_capabilities():
    stop = StopCondition(Budget(max_capabilities=2))
    state = ScanState(steps_executed=2)
    assert stop.check(state) is StopReason.BUDGET_CAPABILITIES
    assert StopCondition(Budget(max_capabilities=3)).check(state) is None


# --------------------------------------------------------------------------- #
# CognitiveEngine — loop ponta a ponta
# --------------------------------------------------------------------------- #
def _engine_registry() -> PluginRegistry:
    return PluginRegistry(
        [
            _spec(
                "subfinder",
                (C.SUBDOMAIN_ENUMERATION,),
                perspectives=(P.EXTERNAL,),
                findings=[_finding("Subdomínio: app.example.com", "app.example.com", "subfinder")],
            ),
            _spec(
                "naabu",
                (C.PORT_DISCOVERY,),
                speed="high",
                preferred=("external",),
                findings=[_finding("Porta aberta 443/tcp (https)", "example.com:443", "naabu")],
            ),
        ]
    )


def test_engine_runs_recon_end_to_end():
    reg = _engine_registry()
    engine = CognitiveEngine(reg)
    scope = build_scope(None, ["example.com"], P.EXTERNAL)
    goal = Goal.build(GoalKind.ATTACK_SURFACE, ["example.com"])
    report = engine.run(goal, scope=scope)
    # produziu findings reais (via execução determinística, não IA).
    assert len(report.findings) >= 2
    actions = {d.action for d in report.decisions}
    assert "selected" in actions and "executed" in actions
    # capacidades sem plugin viram sugestão/scaffold, nunca fingem rodar.
    assert "suggested" in actions
    assert report.stop_reason in (StopReason.PLAN_EXHAUSTED, StopReason.NO_NEW_EVIDENCE)
    assert report.ai_used is False  # sem IA → determinístico


def test_engine_plan_only_does_not_execute():
    reg = _engine_registry()
    engine = CognitiveEngine(reg)
    goal = Goal.build(GoalKind.ATTACK_SURFACE, ["example.com"])
    _, decisions = engine.plan_only(goal)
    # dry-run: só decisões de seleção/scaffold, nenhuma "executed".
    assert decisions
    assert all(d.action != "executed" for d in decisions)


def test_engine_scaffold_agent_capability_is_suggested_not_executed():
    reg = PluginRegistry([_spec("adx", (C.AD_ENUMERATION,))])  # há plugin, mas agente é scaffold
    engine = CognitiveEngine(reg)
    scope = build_scope(None, ["10.0.0.5"], P.INTERNAL)
    goal = Goal.build(GoalKind.AD_ENUMERATION, ["10.0.0.5"])
    report = engine.run(goal, scope=scope)
    scaffolds = [d for d in report.decisions if d.action == "scaffold"]
    assert scaffolds  # agente não construído → sugerido, não executado
    assert not report.findings


def test_safe_execution_enforces_scope():
    scope = _hard_scope("example.com", perspective=P.EXTERNAL)  # trava dura opt-in
    ex = SafeExecution(scope)
    spec = _spec("naabu", (C.PORT_DISCOVERY,))
    # alvo fora do escopo autorizado deve ser bloqueado (trava dura §2).
    with pytest.raises(Exception):
        ex.execute(spec, "attacker-controlled.example.net", P.EXTERNAL)


def test_engine_uses_agentic_planner_when_ai_available():
    # com IA disponível, o engine usa o AgenticPlanner (a IA comanda o plano).
    comp = _FakeCompletion(
        '{"plan": ["port_discovery", "subdomain_enumeration"], "stop_when": "sem evidência nova"}'
    )
    engine = CognitiveEngine(_engine_registry(), completion=comp)
    scope = build_scope(None, ["example.com"], P.EXTERNAL)
    report = engine.run(Goal.build(GoalKind.ATTACK_SURFACE, ["example.com"]), scope=scope)
    assert report.planner_name == "agentic"
    assert report.ai_used is True
    assert len(report.findings) >= 2  # a IA comandou, o engine executou de verdade
    # a timeline registra o raciocínio inicial da IA (sem caixa-preta).
    assert any(d.action == "planned" for d in report.decisions)


def test_engine_refuses_out_of_scope_target():
    # DoD: recusa de alvo fora de escopo é um bloqueio real, registrado.
    reg = _engine_registry()
    engine = CognitiveEngine(reg)
    scope = _hard_scope("example.com", perspective=P.EXTERNAL)  # trava dura: só example.com
    # objetivo mira um alvo NÃO autorizado → cada execução é recusada pelo escopo.
    goal = Goal.build(GoalKind.ATTACK_SURFACE, ["attacker-controlled.example.net"])
    report = engine.run(goal, scope=scope)
    skipped = [d for d in report.decisions if d.action == "skipped"]
    assert skipped and all("fora de escopo" in d.detail for d in skipped)
    assert not report.findings  # nada rodou contra o alvo não autorizado


def test_network_agent_owns_smb_and_nse_built():
    # As capacidades de enumeração de rede (SMB/Samba, NSE) têm agente REAL —
    # senão a cascata do "achou Samba" só sugeriria, nunca executaria.
    from eigan.engine.cognitive import AgentRegistry

    reg = AgentRegistry.default()
    smb = reg.for_capability(C.SMB_ENUMERATION)
    nse = reg.for_capability(C.NSE_VULN_SCAN)
    assert smb is not None and smb.built and smb.name == "network"
    assert nse is not None and nse.built


def test_replan_smb_finding_chains_to_enumeration_and_nse():
    # O exemplo do dono: nmap acha 445 (Samba) → a cascata encadeia enum4linux
    # (enumeração SMB) e nmap-nse (volta ao nmap com scripts NSE de SMB).
    smb_rule = CascadeRule(
        execute=("enum4linux", "nmap-nse"), port=(445, 139), reason="SMB/Samba exposto"
    )
    nmap = _spec("nmap", (C.PORT_DISCOVERY,), triggers=(smb_rule,))
    enum = _spec("enum4linux", (C.SMB_ENUMERATION,))
    nse = _spec("nmap-nse", (C.NSE_VULN_SCAN,), tool="nmap")
    reg = PluginRegistry([nmap, enum, nse])
    planner = DeterministicPlanner(reg, CascadeGraph.from_registry(reg))
    goal = Goal.build(GoalKind.NETWORK_ASSESSMENT, ["10.0.0.5"])
    state = ScanState(
        new_findings=[_finding("Porta aberta 445/tcp (microsoft-ds)", "10.0.0.5:445", "nmap")]
    )
    plan = Plan([])
    planner.replan(goal, state, plan)
    caps = plan.capabilities()
    assert C.SMB_ENUMERATION in caps  # enumeração dedicada de Samba
    assert C.NSE_VULN_SCAN in caps  # volta ao nmap com NSE
    assert all(s.origin == "cascade" for s in plan.steps)


def test_engine_without_ai_still_delivers_scan():
    # fallback: sem chave de IA, o loop determinístico entrega scan + findings.
    engine = CognitiveEngine(_engine_registry())  # completion=None
    scope = build_scope(None, ["example.com"], P.EXTERNAL)
    report = engine.run(Goal.build(GoalKind.ATTACK_SURFACE, ["example.com"]), scope=scope)
    assert report.ai_used is False
    assert report.planner_name == "deterministic"
    assert report.findings
