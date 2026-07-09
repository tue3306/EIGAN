"""Integração da orquestração em cascata (engine/cascade_orchestrator.py).

Usa plugins fake (sem binário externo) para provar, de forma determinística:
* o pipeline produz um finding de porta;
* a cascata dispara a ferramenta declarada e a executa (segunda onda);
* uma ferramenta sugerida mas indisponível é registrada como "não executada".
"""

from __future__ import annotations

from vulnforge.capability import Capability, Category
from vulnforge.engine.base import BaseToolPlugin, ToolResult
from vulnforge.engine.cascade import CascadeRule
from vulnforge.engine.cascade_orchestrator import CascadeOrchestrator
from vulnforge.engine.plugin import PluginMetadata, PluginSpec
from vulnforge.engine.registry import PluginRegistry
from vulnforge.findings.schema import Confidence, Finding, Severity
from vulnforge.perspective import Perspective
from vulnforge.security.scope import Scope


class _FakePortScanner(BaseToolPlugin):
    binary = "true"
    name = "fakescan"

    def available(self) -> bool:
        return True

    def build_args(self, target, **o):
        return []

    def parse(self, result: ToolResult, target: str):
        return []

    def scan(self, target, **o):
        return [
            Finding(
                title="Porta aberta 445/tcp (microsoft-ds)",
                severity=Severity.INFO,
                affected_asset=f"{target}:445",
                source_tool="fakescan",
                confidence=Confidence.FIRM,
            )
        ]


class _FakeEnum(BaseToolPlugin):
    binary = "true"
    name = "fakeenum"

    def available(self) -> bool:
        return True

    def build_args(self, target, **o):
        return []

    def parse(self, result: ToolResult, target: str):
        return []

    def scan(self, target, **o):
        return [
            Finding(
                title="SMB anônimo permite enumeração",
                severity=Severity.MEDIUM,
                affected_asset=target,
                source_tool="fakeenum",
            )
        ]


def _spec(name, caps, runner, triggers=(), roadmap=False):
    meta = PluginMetadata(
        name=name,
        category=Category.RED,
        capabilities=tuple(caps),
        supported_perspectives=(Perspective.INTERNAL,),
        tool=name,
        roadmap=roadmap,
        triggers_on=tuple(triggers),
    )
    return PluginSpec(metadata=meta, runner=(None if roadmap else runner))


def _registry():
    scanner = _spec(
        "fakescan",
        [Capability.PORT_DISCOVERY],
        _FakePortScanner(),
        triggers=[
            CascadeRule(execute=("fakeenum", "fakeroadmap"), port=(445,), reason="SMB exposto"),
        ],
    )
    # fakeenum tem capability fora do pipeline interno → só roda por cascata.
    enum = _spec("fakeenum", [Capability.COMPLIANCE_AUDIT], _FakeEnum())
    roadmap = _spec("fakeroadmap", [Capability.AD_ENUMERATION], None, roadmap=True)
    return PluginRegistry([scanner, enum, roadmap])


def _scope():
    return Scope(
        authorized=True,
        engagement="test",
        hosts=["10.0.0.5"],
        perspective=Perspective.INTERNAL,
    )


def test_cascade_executes_second_wave_and_logs():
    events: list[dict] = []

    class Sink:
        def emit(self, e):
            events.append(e)

    orch = CascadeOrchestrator(store=None, registry=_registry(), risk=None)
    report = orch.run(
        ["10.0.0.5"],
        scope=_scope(),
        perspective=Perspective.INTERNAL,
        profile="quick",
        sink=Sink(),
    )

    tools = {f.source_tool for f in report.findings}
    assert "fakescan" in tools  # pipeline
    assert "fakeenum" in tools  # segunda onda (cascata) executou de fato

    casc = [e for e in events if e["type"] == "cascade_log"]
    executed = {e["tool"] for e in casc if e["executed"]}
    suggested = {e["tool"] for e in casc if not e["executed"]}
    assert "fakeenum" in executed
    # roadmap: sugerido, honestamente NÃO executado
    assert "fakeroadmap" in suggested
    # todo disparo carrega justificativa
    assert all(e["reason"] for e in casc)


def test_cascade_emits_realtime_event_sequence():
    events: list[dict] = []

    class Sink:
        def emit(self, e):
            events.append(e)

    orch = CascadeOrchestrator(store=None, registry=_registry(), risk=None)
    orch.run(
        ["10.0.0.5"], scope=_scope(), perspective=Perspective.INTERNAL, profile="quick", sink=Sink()
    )

    types = [e["type"] for e in events]
    assert types[0] == "scan_status"
    assert "phase_started" in types
    assert "discovery" in types
    assert "analysis_complete" in types
    assert types[-1] == "scan_status" and events[-1]["status"] == "completed"


def test_discovery_event_advertises_cascade_tools():
    events: list[dict] = []

    class Sink:
        def emit(self, e):
            events.append(e)

    orch = CascadeOrchestrator(store=None, registry=_registry(), risk=None)
    orch.run(
        ["10.0.0.5"], scope=_scope(), perspective=Perspective.INTERNAL, profile="quick", sink=Sink()
    )

    port_disc = [
        e for e in events if e["type"] == "discovery" and e["finding"]["source_tool"] == "fakescan"
    ]
    assert port_disc, "esperava um evento de descoberta da porta"
    assert "fakeenum" in port_disc[0]["cascade_triggered"]
