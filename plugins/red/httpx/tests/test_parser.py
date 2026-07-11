"""Teste do parser do httpx (serviços web vivos)."""

from plugins.red.httpx.parser import parse
from eigan.engine.base import ToolResult


def test_httpx_parse_web_alive():
    out = '{"url":"https://h/","status_code":200,"tech":["nginx"],"title":"Home"}'
    findings = parse(ToolResult(0, out, ""), "https://h/")
    assert len(findings) == 1
    assert findings[0].affected_asset == "https://h/"
    assert "nginx" in findings[0].description


def test_httpx_ignores_garbage():
    assert parse(ToolResult(0, "oops\n", ""), "x") == []
