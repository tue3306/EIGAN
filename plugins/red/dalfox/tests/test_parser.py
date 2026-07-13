"""Testes do parser do dalfox — JSONL de achados de XSS."""

from plugins.red.dalfox.parser import parse
from plugins.red.dalfox.runner import DalfoxRunner

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Severity

_JSONL = (
    '{"type":"V","inject_type":"inHTML-URL","poc":"https://x/?q=<svg onload=alert(1)>",'
    '"param":"q","evidence":"41 line","cwe":"CWE-79"}\n'
    '{"type":"G","param":"s","evidence":"grep"}\n'
    "linha-nao-json"
)


def test_verified_xss_is_high_and_confirmed():
    findings = parse(ToolResult(0, _JSONL, ""), "https://x/search?q=1")
    assert len(findings) == 2  # V e G; a linha não-JSON é ignorada
    v = next(f for f in findings if "verificado" in f.title)
    assert v.severity is Severity.HIGH
    assert v.confidence is Confidence.CONFIRMED
    assert v.cwe == "CWE-79" and "q" in v.title
    assert all(f.source_tool == "dalfox" for f in findings)


def test_empty_yields_nothing():
    assert parse(ToolResult(0, "", ""), "x") == []


def test_build_args_use_jsonl_and_url_mode():
    args = DalfoxRunner().build_args("https://x/?q=1")
    assert args[0] == "url" and "https://x/?q=1" in args
    assert "jsonl" in args
