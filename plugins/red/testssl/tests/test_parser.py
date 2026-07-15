"""Testes do parser do testssl — lista de findings JSON, mapa de severidade."""

from eigan.engine.base import ToolResult
from eigan.findings.schema import Severity
from plugins.red.testssl.parser import parse
from plugins.red.testssl.runner import TestsslRunner

_JSON = (
    "["
    '{"id":"SSLv3","port":"443","severity":"HIGH","finding":"SSLv3 oferecido (inseguro)"},'
    '{"id":"heartbleed","port":"443","severity":"CRITICAL","finding":"vulnerável","cve":"CVE-2014-0160"},'
    '{"id":"cipher_order","port":"443","severity":"OK","finding":"ok"},'
    '{"id":"BREACH","port":"443","severity":"WARN","finding":"potencialmente vulnerável"}'
    "]"
)


def test_maps_severity_and_drops_ok():
    findings = parse(ToolResult(0, _JSON, ""), "https://x")
    # OK é descartado → sobram 3 (HIGH, CRITICAL, WARN→LOW)
    assert len(findings) == 3
    hb = next(f for f in findings if "heartbleed" in f.title)
    assert hb.severity is Severity.CRITICAL
    assert any("CVE-2014-0160" in r for r in hb.references)
    warn = next(f for f in findings if "BREACH" in f.title)
    assert warn.severity is Severity.LOW
    assert all(f.source_tool == "testssl" for f in findings)


def test_empty_yields_nothing():
    assert parse(ToolResult(0, "", ""), "x") == []
    assert parse(ToolResult(0, "not-json", ""), "x") == []


def test_build_args_use_jsonfile():
    args = TestsslRunner().build_args("https://x", outfile="/tmp/t.json")
    assert "--jsonfile-pretty" in args and "/tmp/t.json" in args
    assert "--fast" in args and args[-1] == "https://x"
