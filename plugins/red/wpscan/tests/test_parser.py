"""Testes do parser do wpscan — versão, vulnerabilidades, usuários, findings."""

from eigan.engine.base import ToolResult
from eigan.findings.schema import Severity
from plugins.red.wpscan.parser import parse
from plugins.red.wpscan.runner import WpscanRunner

_JSON = (
    '{"target_url":"https://wp.example/","version":{"number":"5.2","found_by":"meta",'
    '"vulnerabilities":[{"title":"XSS no core","references":{"cve":["2019-1234"]}}]},'
    '"interesting_findings":[{"url":"https://wp.example/xmlrpc.php","to_s":"XML-RPC habilitado","type":"xmlrpc"}],'
    '"users":{"admin":{},"editor":{}}}'
)


def test_parses_version_vuln_findings_and_users():
    fs = parse(ToolResult(0, _JSON, ""), "https://wp.example/")
    titles = [f.title for f in fs]
    assert any("WordPress 5.2 detectado" in t for t in titles)
    vuln = next(f for f in fs if "XSS no core" in f.title)
    assert vuln.severity is Severity.HIGH
    assert any("CVE-2019-1234" in r for r in vuln.references)
    users = next(f for f in fs if "usuário" in f.title)
    assert users.severity is Severity.LOW and users.cwe == "CWE-200"
    assert any("XML-RPC" in f.title for f in fs)
    assert all(f.source_tool == "wpscan" for f in fs)


def test_empty_or_bad_json_yields_nothing():
    assert parse(ToolResult(0, "", ""), "x") == []
    assert parse(ToolResult(0, "not json", ""), "x") == []


def test_build_args_json_and_optional_token(monkeypatch):
    monkeypatch.delenv("WPSCAN_API_TOKEN", raising=False)
    args = WpscanRunner().build_args("https://wp.example/")
    assert "--url" in args and "--format" in args and "json" in args
    assert "--api-token" not in args
    monkeypatch.setenv("WPSCAN_API_TOKEN", "tok")
    assert "--api-token" in WpscanRunner().build_args("https://wp.example/")
