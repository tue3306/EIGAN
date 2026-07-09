"""Testes do pipeline por perspectiva e da resolução por capability do orquestrador."""

import pytest

from vulnforge.capability import Capability, Category
from vulnforge.engine.base import BaseToolPlugin, ToolResult
from vulnforge.engine.orchestrator import Orchestrator
from vulnforge.engine.pipeline import stages_for
from vulnforge.engine.plugin import PluginMetadata, PluginSpec
from vulnforge.engine.registry import PluginRegistry
from vulnforge.findings.schema import Finding, Severity
from vulnforge.perspective import Perspective
from vulnforge.security.scope import PerspectiveViolation, Scope

EXTERNAL = Perspective.EXTERNAL
INTERNAL = Perspective.INTERNAL


class FakePlugin(BaseToolPlugin):
    """Runner de teste: sempre disponível, emite 1 finding, sem executar nada."""

    binary = "fake"

    def __init__(self, name: str) -> None:
        self.name = name

    def available(self) -> bool:
        return True

    def build_args(self, target, **_):
        return [target]

    def scan(self, target, **_):
        return [
            Finding(
                title=f"{self.name} finding",
                severity=Severity.LOW,
                affected_asset=target,
                source_tool=self.name,
            )
        ]

    def parse(self, result: ToolResult, target):  # não usado
        return []


def _spec(name, caps, perspectives, category=Category.RED) -> PluginSpec:
    meta = PluginMetadata(
        name=name,
        category=category,
        capabilities=tuple(caps),
        supported_perspectives=tuple(perspectives),
        tool=name,
    )
    return PluginSpec(metadata=meta, runner=FakePlugin(name))


def _registry(*specs) -> PluginRegistry:
    return PluginRegistry(list(specs))


def test_stages_for_external_has_subdomain_internal_does_not():
    ext_names = [s.name for s in stages_for(EXTERNAL, "standard")]
    int_names = [s.name for s in stages_for(INTERNAL, "standard")]
    assert "subdomain" in ext_names
    assert "subdomain" not in int_names
    assert "host-discovery" in int_names


def test_profile_quick_restricts_stages():
    full = stages_for(EXTERNAL, "standard")
    quick = stages_for(EXTERNAL, "quick")
    assert len(quick) < len(full)


def test_orchestrator_resolves_by_capability_and_perspective():
    reg = _registry(
        _spec("subfinder", [Capability.SUBDOMAIN_ENUMERATION], [EXTERNAL]),
        _spec("naabu", [Capability.PORT_DISCOVERY], [EXTERNAL, INTERNAL]),
        _spec(
            "nmap",
            [Capability.HOST_DISCOVERY, Capability.PORT_DISCOVERY, Capability.SERVICE_DETECTION],
            [EXTERNAL, INTERNAL],
        ),
    )
    orch = Orchestrator(store=None, registry=reg)
    scope = Scope(authorized=True, hosts=["10.0.0.5"], perspective=INTERNAL)

    report = orch.run(["10.0.0.5"], scope=scope, perspective=INTERNAL, profile="quick")
    tools_used = {f.source_tool for f in report.findings}
    # subfinder (só SUBDOMAIN_ENUMERATION) não tem estágio em INTERNAL => não roda.
    assert "subfinder" not in tools_used
    # naabu/nmap provêem PORT_DISCOVERY/HOST_DISCOVERY => rodam.
    assert "naabu" in tools_used and "nmap" in tools_used
    assert all(f.perspective == INTERNAL for f in report.findings)
    assert report.perspective == INTERNAL


def test_plugin_with_multiple_capabilities_runs_once_per_stage():
    # nmap provê 2 capabilities que caem no MESMO estágio 'ports' (external).
    reg = _registry(
        _spec(
            "nmap", [Capability.PORT_DISCOVERY, Capability.SERVICE_DETECTION], [EXTERNAL, INTERNAL]
        ),
    )
    orch = Orchestrator(store=None, registry=reg)
    scope = Scope(authorized=True, hosts=["example.com"], perspective=EXTERNAL)
    report = orch.run(["example.com"], scope=scope, perspective=EXTERNAL, profile="quick")
    # dedupe por nome no estágio: um único finding do nmap, não dois.
    assert [f.source_tool for f in report.findings].count("nmap") == 1


def test_orchestrator_blocks_public_target_internal():
    reg = _registry(_spec("naabu", [Capability.PORT_DISCOVERY], [EXTERNAL, INTERNAL]))
    orch = Orchestrator(store=None, registry=reg)
    scope = Scope(authorized=True, hosts=["8.8.8.8"], perspective=INTERNAL)
    with pytest.raises(PerspectiveViolation):
        orch.run(["8.8.8.8"], scope=scope, perspective=INTERNAL, profile="quick")
