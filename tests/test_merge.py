"""Testes do merge/correlação entre scans."""

from eigan.analysis.merge import merge_findings, merge_summary
from eigan.findings.schema import Finding, Severity
from eigan.findings.store import FindingStore


def _store_two_scans(tmp_path) -> tuple[FindingStore, int, int]:
    store = FindingStore(tmp_path / "m.db")
    s1 = store.create_scan("alvo-a", "standard", ["a.example"])
    store.add_findings(
        s1,
        [
            Finding(
                title="Porta 80",
                severity=Severity.INFO,
                affected_asset="a.example:80",
                source_tool="naabu",
            ),
            Finding(
                title="XSS",
                severity=Severity.HIGH,
                affected_asset="a.example",
                source_tool="dalfox",
                cwe="CWE-79",
            ),
        ],
    )
    store.finish_scan(s1)
    s2 = store.create_scan("alvo-b", "standard", ["b.example"])
    store.add_findings(
        s2,
        [
            Finding(
                title="SQLi",
                severity=Severity.CRITICAL,
                affected_asset="b.example",
                source_tool="sqlmap",
                cwe="CWE-89",
            ),
        ],
    )
    store.finish_scan(s2)
    return store, s1, s2


def test_merge_combines_and_ranks(tmp_path):
    store, s1, s2 = _store_two_scans(tmp_path)
    merged, meta = merge_findings(store, [s1, s2])
    assert len(merged) == 3
    assert merged[0].severity is Severity.CRITICAL  # ordenado por risco/severidade
    assert set(meta["targets"]) == {"a.example", "b.example"}
    assert meta["per_scan"] == {s1: 2, s2: 1}


def test_merge_summary_shape(tmp_path):
    store, s1, s2 = _store_two_scans(tmp_path)
    summ = merge_summary(store, [s1, s2])
    assert summ["count"] == 3
    assert summ["severity"]["critical"] == 1 and summ["severity"]["high"] == 1
    assert summ["targets"] == ["a.example", "b.example"]
    assert len(summ["findings"]) == 3


def test_merge_endpoint_validates_and_returns(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import eigan.api.app as app_mod

    store, s1, s2 = _store_two_scans(tmp_path)
    store.close()
    monkeypatch.setenv("EIGAN_DB", str(tmp_path / "m.db"))
    c = TestClient(app_mod.app)
    r = c.post("/api/v1/scans/merge", json={"scan_ids": [s1, s2]})
    assert r.status_code == 200 and r.json()["count"] == 3
    # scan inexistente → 404
    assert c.post("/api/v1/scans/merge", json={"scan_ids": [s1, 9999]}).status_code == 404
    # menos de 2 → 422 (validação do pydantic)
    assert c.post("/api/v1/scans/merge", json={"scan_ids": [s1]}).status_code == 422
