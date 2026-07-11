"""Testes de schema, dedup e store de findings."""

import tempfile
from pathlib import Path

from eigan.findings.dedup import deduplicate
from eigan.findings.schema import CVSS, Finding, Severity
from eigan.findings.store import FindingStore


def _f(**kw):
    base = dict(
        title="SQLi",
        severity=Severity.HIGH,
        affected_asset="host:80",
        source_tool="nuclei",
        cwe="CWE-89",
    )
    base.update(kw)
    return Finding(**base)


def test_severity_from_cvss():
    assert Severity.from_cvss(9.5) == Severity.CRITICAL
    assert Severity.from_cvss(7.0) == Severity.HIGH
    assert Severity.from_cvss(4.0) == Severity.MEDIUM
    assert Severity.from_cvss(0.1) == Severity.LOW
    assert Severity.from_cvss(0.0) == Severity.INFO


def test_cwe_normalized():
    assert _f(cwe="cwe-89").cwe == "CWE-89"


def test_fingerprint_stable_across_tools():
    a = _f(source_tool="nuclei")
    b = _f(source_tool="nikto")
    assert a.fingerprint == b.fingerprint


def test_dedup_merges_and_keeps_highest_severity():
    a = _f(source_tool="nuclei", severity=Severity.MEDIUM, references=["r1"])
    b = _f(source_tool="nikto", severity=Severity.HIGH, references=["r2"])
    out = deduplicate([a, b])
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH
    assert "nikto" in out[0].correlated_sources
    assert set(out[0].references) == {"r1", "r2"}


def test_store_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        store = FindingStore(Path(d) / "t.db")
        sid = store.create_scan("eng", "standard", ["host"])
        store.add_findings(sid, [_f(cvss=CVSS(version="3.1", score=8.8))])
        store.finish_scan(sid)
        got = store.get_findings(sid)
        assert len(got) == 1
        assert got[0].cvss.version == "3.1"
        assert store.get_scan(sid)["finished_at"] is not None


def test_store_dedup_by_fingerprint():
    with tempfile.TemporaryDirectory() as d:
        store = FindingStore(Path(d) / "t.db")
        sid = store.create_scan("eng", "standard", ["host"])
        store.add_findings(sid, [_f(), _f()])  # mesmo fingerprint
        assert len(store.get_findings(sid)) == 1
