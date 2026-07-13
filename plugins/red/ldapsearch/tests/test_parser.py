"""Testes do parser do ldapsearch — RootDSE (LDIF) por bind anônimo."""

from plugins.red.ldapsearch.parser import parse
from plugins.red.ldapsearch.runner import LdapsearchRunner, _host

from eigan.engine.base import ToolResult
from eigan.findings.schema import Severity

_LDIF = """# extended LDIF
dn:
namingContexts: dc=corp,dc=local
namingContexts: CN=Configuration,dc=corp,dc=local
supportedLDAPVersion: 3
"""


def test_anonymous_bind_rootdse_is_medium():
    fs = parse(ToolResult(0, _LDIF, ""), "10.0.0.5")
    assert len(fs) == 1
    f = fs[0]
    assert f.severity is Severity.MEDIUM and f.cwe == "CWE-200"
    assert "dc=corp,dc=local" in f.description
    assert f.source_tool == "ldapsearch"


def test_no_response_yields_nothing():
    assert parse(ToolResult(1, "", "ldap_bind: Invalid credentials"), "x") == []


def test_host_extraction_and_args():
    assert _host("ldap://10.0.0.5:389") == "10.0.0.5"
    args = LdapsearchRunner().build_args("dc01.corp.local")
    assert "-x" in args and "-H" in args and "ldap://dc01.corp.local" in args
