"""Testes do parser do nuclei (saída de amostra, sem executar a ferramenta)."""

from plugins.red.nuclei.parser import parse
from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Severity


def test_nuclei_parse_jsonl():
    line = (
        '{"template-id":"CVE-test","matched-at":"http://h/","info":'
        '{"name":"Test","severity":"high","classification":'
        '{"cvss-score":8.8,"cvss-metrics":"CVSS:3.1/AV:N","cwe-id":["cwe-89"],'
        '"cve-id":["CVE-2024-0001"]}}}'
    )
    findings = parse(ToolResult(0, line, ""), "http://h/")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.cvss.version == "3.1"
    assert f.cwe == "CWE-89"
    # CVE do template não confirmado contra NVD => UNVERIFIED
    assert f.confidence == Confidence.UNVERIFIED
    assert any("CVE-2024-0001" in r for r in f.references)


def test_nuclei_parse_ignores_garbage_lines():
    assert parse(ToolResult(0, "not json\n\n", ""), "x") == []
