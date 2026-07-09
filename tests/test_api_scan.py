"""Testes da API de scan em tempo real (api/app.py + scan_manager.py).

Cobre a jornada da UI sem tocar CLI: recusa sem consent, início de job,
conclusão, cascade-log e streaming por WebSocket. Não depende de ferramentas
externas — o pipeline roda e conclui vazio quando nada está instalado.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNFORGE_DB", str(tmp_path / "api.db"))
    # reimporta o app com o DB temporário e manager limpo.
    import importlib

    from vulnforge.api import app as app_mod
    from vulnforge.api.scan_manager import ScanManager
    from vulnforge.engine.registry import PluginRegistry

    importlib.reload(app_mod)
    # Registry vazio: os testes de API exercem o plumbing (consent, lifecycle,
    # eventos, WebSocket), não ferramentas reais. Assim o scan conclui na hora e
    # de forma determinística mesmo em hosts com nmap/naabu instalados (Kali).
    app_mod._manager = ScanManager(str(tmp_path / "api.db"), registry=PluginRegistry([]))
    return TestClient(app_mod.app)


def _wait(client, job_id, timeout=8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = client.get(f"/api/v1/jobs/{job_id}").json()
        if s["status"] in ("completed", "failed", "cancelled"):
            return s
        time.sleep(0.05)
    raise AssertionError("job não concluiu no tempo esperado")


def test_scan_requires_authorization(client):
    r = client.post(
        "/api/v1/scans",
        json={"targets": ["10.0.0.5"], "perspective": "internal", "objective": "quick"},
    )
    assert r.status_code == 403  # consent gate preservado


def test_scan_lifecycle_and_cascade_log(client):
    r = client.post(
        "/api/v1/scans",
        json={
            "targets": ["10.0.0.5"],
            "perspective": "internal",
            "objective": "quick",
            "authorized": True,
        },
    )
    assert r.status_code == 202
    job_id = r.json()["id"]
    assert r.json()["status"] in ("queued", "running")

    final = _wait(client, job_id)
    assert final["status"] == "completed"

    prog = client.get(f"/api/v1/jobs/{job_id}/progress").json()
    types = [e["type"] for e in prog["events"]]
    # registry vazio (hermético): sem fases, mas o ciclo completo é emitido.
    assert "analysis_complete" in types
    assert types[-1] == "scan_status"

    casc = client.get(f"/api/v1/jobs/{job_id}/cascade-log").json()
    assert "cascade_log" in casc  # existe mesmo que vazio (sem ferramentas)


def test_invalid_perspective_is_rejected(client):
    r = client.post(
        "/api/v1/scans",
        json={"targets": ["10.0.0.5"], "perspective": "lunar", "authorized": True},
    )
    assert r.status_code == 400


def test_websocket_streams_until_end(client):
    job = client.post(
        "/api/v1/scans",
        json={
            "targets": ["10.0.0.5"],
            "perspective": "internal",
            "objective": "quick",
            "authorized": True,
        },
    ).json()
    types = []
    with client.websocket_connect(f"/ws/scans/{job['id']}/progress") as ws:
        for _ in range(60):
            e = ws.receive_json()
            types.append(e["type"])
            if e["type"] == "stream_end":
                break
    assert types[-1] == "stream_end"
    assert "scan_status" in types


def test_findings_and_assets_endpoints(client):
    # sem scan ainda: endpoints respondem vazio, não 500.
    f = client.get("/api/v1/findings").json()
    assert f["count"] == 0 and f["findings"] == []
    a = client.get("/api/v1/assets").json()
    assert a["assets"] == []


def test_unknown_job_is_404(client):
    assert client.get("/api/v1/jobs/job-999").status_code == 404
