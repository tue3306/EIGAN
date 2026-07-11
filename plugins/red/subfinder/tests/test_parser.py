"""Teste do parser do subfinder (subdomínios, com dedup)."""

from plugins.red.subfinder.parser import parse
from eigan.engine.base import ToolResult


def test_subfinder_parse_and_dedup():
    out = '{"host":"a.example.com"}\n{"host":"a.example.com"}\nb.example.com'
    findings = parse(ToolResult(0, out, ""), "example.com")
    assets = {f.affected_asset for f in findings}
    assert assets == {"a.example.com", "b.example.com"}
    assert all(f.attack_technique == "T1590" for f in findings)
