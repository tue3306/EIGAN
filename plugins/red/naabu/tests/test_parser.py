"""Teste do parser do naabu (JSONL de portas)."""

from plugins.red.naabu.parser import parse
from eigan.engine.base import ToolResult
from eigan.findings.schema import Severity


def test_naabu_parse_ports():
    out = '{"ip":"10.0.0.5","port":22,"protocol":"tcp"}\n{"ip":"10.0.0.5","port":80}'
    findings = parse(ToolResult(0, out, ""), "10.0.0.5")
    assert {f.affected_asset for f in findings} == {"10.0.0.5:22", "10.0.0.5:80"}
    assert all(f.severity == Severity.INFO for f in findings)


def test_naabu_ignores_lines_without_port():
    assert parse(ToolResult(0, '{"ip":"x"}\nnot-json', ""), "x") == []
