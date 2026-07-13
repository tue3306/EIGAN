"""Testes do parser do trivy — Results[].Vulnerabilities[] → findings."""

from plugins.blue.trivy.parser import parse
from plugins.blue.trivy.runner import TrivyRunner

from eigan.engine.base import ToolResult
from eigan.findings.schema import Severity

_JSON = (
    '{"Results":[{"Target":"nginx:1.25 (debian 12)","Vulnerabilities":['
    '{"VulnerabilityID":"CVE-2023-1234","PkgName":"openssl","InstalledVersion":"3.0.1",'
    '"FixedVersion":"3.0.2","Severity":"CRITICAL","Title":"Buffer overflow no OpenSSL"},'
    '{"VulnerabilityID":"CVE-2023-1234","PkgName":"openssl","Severity":"CRITICAL"}'  # dup
    "]}]}"
)


def test_parses_cves_and_dedups():
    fs = parse(ToolResult(0, _JSON, ""), "nginx:1.25")
    assert len(fs) == 1  # dedup por cve:pkg:target
    f = fs[0]
    assert f.severity is Severity.CRITICAL
    assert "CVE-2023-1234" in f.title and "openssl" in f.title
    assert any("CVE-2023-1234" in r for r in f.references)
    assert f.source_tool == "trivy" and f.owasp == "A06:2021"


def test_empty_yields_nothing():
    assert parse(ToolResult(0, "", ""), "x") == []
    assert parse(ToolResult(0, "not json", ""), "x") == []


def test_build_args_image_vs_fs(tmp_path):
    assert TrivyRunner().build_args("nginx:1.25")[0] == "image"
    assert TrivyRunner().build_args(str(tmp_path))[0] == "fs"
