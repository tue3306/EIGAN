"""Teste do parser do dnsx (hosts que resolvem)."""

from eigan.engine.base import ToolResult
from plugins.red.dnsx.parser import parse


def test_dnsx_parse_live_host():
    out = '{"host":"h.example.com","a":["1.2.3.4"],"status_code":"NOERROR"}'
    findings = parse(ToolResult(0, out, ""), "h.example.com")
    assert len(findings) == 1
    assert findings[0].affected_asset == "h.example.com"
    assert "1.2.3.4" in findings[0].description


def test_dnsx_skips_nxdomain_without_a():
    out = '{"host":"dead.example.com","status_code":"NXDOMAIN"}'
    assert parse(ToolResult(0, out, ""), "dead.example.com") == []
