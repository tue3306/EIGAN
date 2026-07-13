"""Testes do parser do grype — matches[].vulnerability → findings."""

from plugins.blue.grype.parser import parse
from plugins.blue.grype.runner import GrypeRunner

from eigan.engine.base import ToolResult
from eigan.findings.schema import Severity

_JSON = (
    '{"matches":[{"vulnerability":{"id":"CVE-2022-9999","severity":"High",'
    '"fix":{"versions":["1.2.4"]}},"artifact":{"name":"libfoo","version":"1.2.3"}}]}'
)


def test_parses_grype_match():
    fs = parse(ToolResult(0, _JSON, ""), "alpine:3.18")
    assert len(fs) == 1
    f = fs[0]
    assert f.severity is Severity.HIGH
    assert "CVE-2022-9999" in f.title and "libfoo" in f.title
    assert "corrigido em 1.2.4" in f.description
    assert f.source_tool == "grype"


def test_empty_yields_nothing():
    assert parse(ToolResult(0, "", ""), "x") == []


def test_build_args_json():
    args = GrypeRunner().build_args("alpine:3.18")
    assert args[0] == "alpine:3.18" and "-o" in args and "json" in args
