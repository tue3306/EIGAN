"""Testes do parser do sqlmap — fixture do stdout de injeção confirmada."""

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Severity
from plugins.red.sqlmap.parser import parse
from plugins.red.sqlmap.runner import SqlmapRunner

_CONFIRMED = """
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
---
[INFO] the back-end DBMS is MySQL
web application technology: Apache
back-end DBMS: MySQL >= 5.0
"""


def test_confirmed_injection_is_critical():
    findings = parse(ToolResult(0, _CONFIRMED, ""), "https://x/item.jsp?id=1")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.CRITICAL
    assert f.cwe == "CWE-89" and f.owasp == "A03:2021"
    assert "id" in f.title
    assert f.confidence is Confidence.CONFIRMED
    assert "MySQL" in f.description


def test_no_injection_yields_nothing():
    out = "[INFO] all tested parameters do not appear to be injectable."
    assert parse(ToolResult(0, out, ""), "https://x/") == []


def test_build_args_are_safe_nondestructive():
    args = SqlmapRunner().build_args("https://x/?id=1")
    assert "--batch" in args
    # nunca modos destrutivos por padrão
    assert not any(a in ("--dump", "--os-shell", "--file-read", "--all") for a in args)
