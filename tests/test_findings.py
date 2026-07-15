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


def test_dedup_merge_preserves_evidence_and_earliest_first_seen():
    """Regressão do merge (correção/veracidade §4, evidência de relatório §12):
    - o antigo `.strip('\\n-')` comia traços/quebras LEGÍTIMOS do conteúdo da
      evidência (ex.: '-----END CERTIFICATE-----') — corrompia o dado no relatório;
    - `first_seen` do merge tem de ser o MAIS ANTIGO observado (não o do primeiro
      da lista) — semântica de 'primeira vez visto'."""
    from datetime import datetime, timezone

    t_early = datetime(2020, 1, 1, tzinfo=timezone.utc)
    t_late = datetime(2020, 6, 1, tzinfo=timezone.utc)
    pem = "-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----"
    a = _f(source_tool="nuclei", evidence="ev-a", first_seen=t_late, last_seen=t_late)
    b = _f(source_tool="testssl", evidence=pem, first_seen=t_early, last_seen=t_early)
    out = deduplicate([a, b])
    assert len(out) == 1
    assert pem in out[0].evidence  # traços do conteúdo preservados, não comidos
    assert "ev-a" in out[0].evidence
    assert out[0].first_seen == t_early  # o mais antigo
    assert out[0].last_seen == t_late  # o mais recente


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


def test_store_none_path_falls_back_to_default(tmp_path, monkeypatch):
    # Um db_path nulo/vazio NÃO deve virar um banco "None"/"" no disco: cai no
    # default seguro (regressão do arquivo-fantasma "None"). Roda em cwd temporário
    # para não sujar o diretório do repositório com um eigan.db.
    monkeypatch.chdir(tmp_path)
    assert FindingStore(None)._path == "eigan.db"
    assert FindingStore("")._path == "eigan.db"
    assert not (tmp_path / "None").exists()
