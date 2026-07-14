"""Testes da persistência incremental + ciclo de vida de scan (ADR-0017).

Cobre o bug crítico de confiabilidade: os findings eram gravados só no _finalize;
um scan morto/timeout perdia TUDO. Agora a gravação é incremental (durável) e o
scan tem status (running/completed/failed/cancelled/partial)."""

from __future__ import annotations

from eigan.capability import Capability
from eigan.engine.cognitive import CognitiveEngine
from eigan.engine.cognitive.feedback import ScanState
from eigan.findings.schema import Finding, Severity
from eigan.findings.store import FindingStore


def _f(title: str, asset: str = "h", tool: str = "nmap") -> Finding:
    return Finding(title=title, severity=Severity.INFO, affected_asset=asset, source_tool=tool)


# ── store: ciclo de vida ──────────────────────────────────────────────────────
def test_create_scan_starts_running(tmp_path):
    st = FindingStore(tmp_path / "s.db")
    sid = st.create_scan("lab", "external/quick", ["example.com"])
    assert st.get_scan(sid)["status"] == "running"


def test_finish_scan_sets_status(tmp_path):
    st = FindingStore(tmp_path / "s.db")
    sid = st.create_scan("lab", "p", ["x"])
    st.finish_scan(sid)
    row = st.get_scan(sid)
    assert row["status"] == "completed" and row["finished_at"]
    st.finish_scan(sid, status="failed")
    assert st.get_scan(sid)["status"] == "failed"


def test_set_status_without_finishing(tmp_path):
    st = FindingStore(tmp_path / "s.db")
    sid = st.create_scan("lab", "p", ["x"])
    st.set_status(sid, "partial")
    row = st.get_scan(sid)
    assert row["status"] == "partial" and row["finished_at"] is None


def test_executed_capabilities_roundtrip(tmp_path):
    st = FindingStore(tmp_path / "s.db")
    sid = st.create_scan("lab", "p", ["x"])
    assert st.get_executed_capabilities(sid) == []
    st.set_executed_capabilities(sid, ["port_discovery", "host_discovery"])
    assert st.get_executed_capabilities(sid) == ["host_discovery", "port_discovery"]


def test_running_scans_lists_only_unfinished(tmp_path):
    st = FindingStore(tmp_path / "s.db")
    a = st.create_scan("lab", "p", ["x"])  # running
    b = st.create_scan("lab", "p", ["y"])
    st.finish_scan(b)  # completed
    c = st.create_scan("lab", "p", ["z"])
    st.set_status(c, "partial")
    ids = {r["id"] for r in st.running_scans()}
    assert a in ids and c in ids and b not in ids


def test_add_findings_upsert_overwrites(tmp_path):
    st = FindingStore(tmp_path / "s.db")
    sid = st.create_scan("lab", "p", ["x"])
    # incremental: grava o finding "cru" (severity info)
    raw = _f("Porta 80", "h:80")
    st.add_findings(sid, [raw])
    assert st.get_findings(sid)[0].severity is Severity.INFO
    # finalize: mesmo fingerprint, agora HIGH (pontuado) — deve SOBRESCREVER, não ignorar
    scored = Finding.model_validate_json(raw.model_dump_json())
    scored.severity = Severity.HIGH
    st.add_findings(sid, [scored])
    got = st.get_findings(sid)
    assert len(got) == 1 and got[0].severity is Severity.HIGH


# ── engine: gravação incremental (durável contra kill) ────────────────────────
def test_persist_incremental_writes_before_finalize(tmp_path):
    """Prova o núcleo do fix: findings de uma onda ficam legíveis ANTES do finalize."""
    store = FindingStore(tmp_path / "s.db")
    sid = store.create_scan("lab", "external/quick", ["example.com"])
    engine = CognitiveEngine.__new__(CognitiveEngine)  # sem __init__: testa o método puro
    engine._store = store  # type: ignore[attr-defined]

    state = ScanState()
    state.executed_capabilities.add(Capability.HOST_DISCOVERY)
    engine._persist_incremental(sid, [_f("Host vivo", "1.2.3.4")], state)

    # o scan AINDA está 'running' (não finalizado), MAS os findings já persistiram
    assert store.get_scan(sid)["status"] == "running"
    persisted = store.get_findings(sid)
    assert len(persisted) == 1 and persisted[0].title == "Host vivo"
    assert store.get_executed_capabilities(sid) == ["host_discovery"]


def test_persist_incremental_noop_without_store():
    engine = CognitiveEngine.__new__(CognitiveEngine)
    engine._store = None  # type: ignore[attr-defined]
    # não levanta mesmo sem store/scan_id
    engine._persist_incremental(None, [_f("x")], ScanState())
