"""Testes do parser do nikto — envelope JSON (lista ou objeto) + severidade."""

from plugins.red.nikto.parser import parse
from plugins.red.nikto.runner import NiktoRunner

from eigan.engine.base import ToolResult
from eigan.findings.schema import Severity

_JSON = (
    '[{"host":"demo","ip":"1.2.3.4","port":"443","vulnerabilities":['
    '{"id":"999104","method":"GET","url":"/","msg":"The X-Frame-Options header is not present."},'
    '{"id":"1","method":"GET","url":"/admin.cgi","msg":"Possible SQL injection in parameter"},'
    '{"method":"GET","url":"/","msg":"Server leaks inodes via ETags"}'
    "]}]"
)


def test_parses_and_grades_severity():
    findings = parse(ToolResult(0, _JSON, ""), "https://demo/")
    assert len(findings) == 3
    hdr = next(f for f in findings if "X-Frame" in f.title)
    assert hdr.severity is Severity.INFO  # cabeçalho → info
    sqli = next(f for f in findings if "SQL injection" in f.title)
    assert sqli.severity is Severity.MEDIUM  # palavra de alto risco → medium
    assert all(f.source_tool == "nikto" for f in findings)
    # url relativa é ancorada no alvo
    assert any(f.affected_asset == "https://demo//admin.cgi" for f in findings)


def test_empty_or_bad_json_yields_nothing():
    assert parse(ToolResult(0, "", ""), "x") == []
    assert parse(ToolResult(0, "not json", ""), "x") == []


def test_build_args_use_json_and_outfile():
    args = NiktoRunner().build_args("https://x/", outfile="/tmp/o.json")
    assert "-Format" in args and "json" in args
    assert "-output" in args and "/tmp/o.json" in args
    assert "-h" in args
