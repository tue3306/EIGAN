"""Testes do grafo de cascata (engine/cascade.py) — puro e determinístico."""

from __future__ import annotations

from vulnforge.engine.cascade import CascadeGraph, CascadeRule, FindingFeatures
from vulnforge.findings.schema import Finding, Severity


def _f(
    title="Porta aberta 445/tcp (microsoft-ds)",
    asset="10.0.0.5:445",
    sev=Severity.INFO,
    tool="nmap",
):
    return Finding(title=title, severity=sev, affected_asset=asset, source_tool=tool)


def test_features_extract_port_service():
    feat = FindingFeatures.of(_f())
    assert feat.port == 445
    assert feat.service == "microsoft-ds"
    assert feat.source_tool == "nmap"


def test_features_handle_bare_host_without_port():
    feat = FindingFeatures.of(_f(title="Apache exposto", asset="site.com"))
    assert feat.port is None
    assert feat.service is None


def test_rule_from_dict_accepts_then_execute_alias():
    rule = CascadeRule.from_dict(
        {"port": [445, 139], "then_execute": ["enum4linux"], "reason": "SMB"}
    )
    assert rule is not None
    assert rule.execute == ("enum4linux",)
    assert rule.port == (445, 139)


def test_rule_without_execute_is_ignored():
    assert CascadeRule.from_dict({"port": [80]}) is None
    assert CascadeRule.from_dict("nonsense") is None


def test_rule_matches_by_port():
    rule = CascadeRule(execute=("enum4linux",), port=(445, 139))
    assert rule.matches(FindingFeatures.of(_f(asset="10.0.0.5:445")))
    assert not rule.matches(FindingFeatures.of(_f(asset="10.0.0.5:22")))


def test_rule_matches_by_severity_min():
    rule = CascadeRule(execute=("poc",), severity_min=Severity.HIGH)
    assert rule.matches(FindingFeatures.of(_f(sev=Severity.CRITICAL)))
    assert not rule.matches(FindingFeatures.of(_f(sev=Severity.MEDIUM)))


def test_rule_matches_by_title_contains():
    rule = CascadeRule(execute=("cve_enrich",), title_contains=("cve-",))
    assert rule.matches(FindingFeatures.of(_f(title="Apache RCE CVE-2021-41773")))
    assert not rule.matches(FindingFeatures.of(_f(title="Porta aberta 80/tcp (http)")))


def test_rule_matches_by_source_tool():
    rule = CascadeRule(execute=("dnsx",), source_tool=("subfinder",))
    assert rule.matches(FindingFeatures.of(_f(tool="subfinder")))
    assert not rule.matches(FindingFeatures.of(_f(tool="nmap")))


def test_describe_uses_explicit_reason_then_falls_back():
    with_reason = CascadeRule(execute=("x",), port=(445,), reason="SMB exposto")
    assert with_reason.describe(FindingFeatures.of(_f())) == "SMB exposto"
    no_reason = CascadeRule(execute=("x",), port=(445,))
    assert "dispara x" in no_reason.describe(FindingFeatures.of(_f()))


def test_graph_dedupes_and_never_triggers_source_tool():
    graph = CascadeGraph(
        rules_by_plugin={
            "a": (CascadeRule(execute=("enum4linux", "nmap"), port=(445,)),),
            "b": (CascadeRule(execute=("enum4linux",), port=(445,)),),  # duplicado
        }
    )
    triggers = graph.triggered_by(_f(tool="nmap"))
    tools = [t.tool for t in triggers]
    assert tools.count("enum4linux") == 1  # deduplicado
    assert "nmap" not in tools  # nunca dispara a própria ferramenta de origem


def test_graph_from_registry_loads_declared_triggers():
    from vulnforge.engine.registry import PluginRegistry

    graph = CascadeGraph.from_registry(PluginRegistry.discover())
    # os plugins reais declaram triggers_on (nmap, naabu, httpx, ...).
    assert "nmap" in graph.rules_by_plugin
    triggers = graph.triggered_by(_f())
    assert any(t.tool == "enum4linux" for t in triggers)
    assert all(t.reason for t in triggers)  # todo disparo é justificado
