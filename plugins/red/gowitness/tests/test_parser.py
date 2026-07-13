"""Testes do parser do gowitness — JSONL de captura → screenshot finding."""

from plugins.red.gowitness.parser import parse
from plugins.red.gowitness.runner import GowitnessRunner

from eigan.engine.base import ToolResult
from eigan.findings.schema import Severity

_JSONL = '{"url":"https://demo.testfire.net/","title":"Altoro Mutual","response_code":200,"filename":"demo.jpeg"}'


def test_parses_screenshot():
    fs = parse(ToolResult(0, _JSONL, ""), "https://demo.testfire.net/")
    assert len(fs) == 1
    f = fs[0]
    assert f.severity is Severity.INFO and f.source_tool == "gowitness"
    assert "Altoro Mutual" in f.title
    assert "demo.jpeg" in f.evidence


def test_empty_yields_nothing():
    assert parse(ToolResult(0, "", ""), "x") == []


def test_build_args_single_mode():
    args = GowitnessRunner().build_args("https://x/")
    assert args[:2] == ["scan", "single"] and "-u" in args and "--write-jsonl" in args
