"""Testes da API + dashboard (FastAPI TestClient sobre um banco semeado)."""

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from eigan.findings.schema import CVSS, Finding, RiskScore, Severity  # noqa: E402
from eigan.findings.store import FindingStore  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db = tmp_path / "api.db"
    store = FindingStore(db)
    sid = store.create_scan("lab", "external/standard", ["http://h/"])
    f = Finding(
        title="SQLi",
        severity=Severity.HIGH,
        affected_asset="http://h/app",
        source_tool="nuclei",
        cwe="CWE-89",
        attack_technique="T1190",
        cvss=CVSS(version="3.1", score=8.8),
    )
    f.risk = RiskScore(score=96.0, kev=True, kev_verified=True)
    store.add_findings(
        sid,
        [
            f,
            Finding(
                title="Porta 80", severity=Severity.INFO, affected_asset="h:80", source_tool="nmap"
            ),
        ],
    )
    store.finish_scan(sid)
    store.close()
    monkeypatch.setenv("EIGAN_DB", str(db))
    from eigan.api.app import app

    return TestClient(app), sid


def test_health_and_meta(client):
    c, _ = client
    assert c.get("/api/v1/health").json()["status"] == "ok"
    m = c.get("/api/v1/meta").json()
    assert "ai_enabled" in m and "ai_key_detected" in m


def test_setup_status_reports_degraded_items(client):
    c, _ = client
    s = c.get("/api/v1/setup").json()
    assert "enabled" in s["ai"] and "key_detected" in s["ai"]
    assert "available" in s["pdf"]
    assert "missing_real" in s["tools"] and "hint" in s["tools"]


def test_report_html_downloads(client):
    c, sid = client
    r = c.get(f"/api/v1/scans/{sid}/report?format=html&style=executive")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "attachment" in r.headers.get("content-disposition", "").lower()


def test_report_json_downloads(client):
    c, sid = client
    assert c.get(f"/api/v1/scans/{sid}/report?format=json").status_code == 200


def test_report_rejects_bad_format(client):
    c, sid = client
    assert c.get(f"/api/v1/scans/{sid}/report?format=xml").status_code == 400


def test_report_missing_scan_404(client):
    c, _ = client
    assert c.get("/api/v1/scans/9999/report").status_code == 404


def test_report_pdf_serves_or_degrades_to_html(client):
    c, sid = client
    r = c.get(f"/api/v1/scans/{sid}/report?format=pdf")
    assert r.status_code == 200
    # Com WeasyPrint + libs → PDF; sem elas → HTML degradado (sinalizado no header).
    if r.headers.get("X-Report-Degraded"):
        assert "text/html" in r.headers["content-type"]
    else:
        assert "application/pdf" in r.headers["content-type"]


def test_stats_and_scan_detail(client):
    c, sid = client
    stats = c.get("/api/v1/stats").json()
    assert stats["scans"] == 1 and stats["kev"] == 1
    detail = c.get(f"/api/v1/scans/{sid}").json()
    assert detail["count"] == 2 and detail["severity"]["high"] == 1


def test_findings_filter(client):
    c, sid = client
    all_f = c.get(f"/api/v1/scans/{sid}/findings").json()
    assert all_f["count"] == 2
    high = c.get(f"/api/v1/scans/{sid}/findings?severity=high").json()
    assert high["count"] == 1 and high["findings"][0]["cwe"] == "CWE-89"


def test_inventory_attack_compliance(client):
    c, sid = client
    inv = c.get(f"/api/v1/scans/{sid}/inventory").json()
    assert inv["summary"]["assets"] >= 1
    atk = c.get(f"/api/v1/scans/{sid}/attack").json()
    assert any(h["technique"] == "T1190" for h in atk["hits"])
    comp = c.get(f"/api/v1/scans/{sid}/compliance").json()
    assert comp["indicative"] is True


def test_dashboard_html(client):
    c, _ = client
    r = c.get("/")
    assert r.status_code == 200 and "EIGAN" in r.text


def test_scan_404(client):
    c, _ = client
    assert c.get("/api/v1/scans/9999/findings").status_code == 404
