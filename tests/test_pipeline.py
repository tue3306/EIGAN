"""Testes do pipeline por perspectiva e do filtro de adapters do orquestrador."""

from vulnforge.engine.base import BaseToolAdapter, ToolResult
from vulnforge.engine.orchestrator import Orchestrator
from vulnforge.engine.pipeline import stages_for
from vulnforge.findings.schema import Finding, Severity
from vulnforge.perspective import Perspective
from vulnforge.security.scope import Scope

EXTERNAL = Perspective.EXTERNAL
INTERNAL = Perspective.INTERNAL


class FakeAdapter(BaseToolAdapter):
    """Adapter de teste: sempre disponível, emite 1 finding, sem executar nada."""

    def __init__(self, name, perspectives):
        self._name = name
        self.supported_perspectives = perspectives

    @property
    def name(self):  # type: ignore[override]
        return self._name

    def available(self):  # não depende de binário real
        return True

    def build_args(self, target, **_):
        return [target]

    def scan(self, target, **_):
        return [Finding(title=f"{self._name} finding", severity=Severity.LOW,
                        affected_asset=target, source_tool=self._name)]

    def parse(self, result: ToolResult, target):  # não usado
        return []


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


def test_orchestrator_filters_by_perspective():
    # subfinder-like: só EXTERNAL. naabu-like: ambos.
    registry = {
        "subfinder": FakeAdapter("subfinder", (EXTERNAL,)),
        "naabu": FakeAdapter("naabu", (EXTERNAL, INTERNAL)),
        "nmap": FakeAdapter("nmap", (EXTERNAL, INTERNAL)),
    }
    orch = Orchestrator(store=None, registry=registry)
    scope = Scope(authorized=True, hosts=["10.0.0.5"], perspective=INTERNAL)

    report = orch.run(["10.0.0.5"], scope=scope, perspective=INTERNAL, profile="quick")
    tools_used = {f.source_tool for f in report.findings}
    # subfinder NÃO deve rodar em INTERNAL; naabu/nmap sim.
    assert "subfinder" not in tools_used
    assert "naabu" in tools_used
    # todos os findings carimbados com a perspectiva do job:
    assert all(f.perspective == INTERNAL for f in report.findings)
    assert report.perspective == INTERNAL


def test_orchestrator_blocks_public_target_internal():
    registry = {"naabu": FakeAdapter("naabu", (EXTERNAL, INTERNAL))}
    orch = Orchestrator(store=None, registry=registry)
    scope = Scope(authorized=True, hosts=["8.8.8.8"], perspective=INTERNAL)
    import pytest
    from vulnforge.security.scope import PerspectiveViolation
    with pytest.raises(PerspectiveViolation):
        orch.run(["8.8.8.8"], scope=scope, perspective=INTERNAL, profile="quick")
