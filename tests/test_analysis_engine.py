"""Testes do Analysis Engine (análise automática da IA) + persistência no store."""

from eigan.analysis.engine import analyze_and_store, analyze_scan
from eigan.findings.schema import Finding, Severity
from eigan.findings.store import FindingStore


class _FakeProvider:
    def __init__(self, reply: str = "RESUMO: risco alto.") -> None:
        self.reply = reply
        self.calls = 0

    def complete(self, system: str, user: str) -> str:
        self.calls += 1
        return self.reply


def _store_with_scan(tmp_path) -> tuple[FindingStore, int]:
    store = FindingStore(tmp_path / "a.db")
    sid = store.create_scan("demo", "standard", ["x"])
    store.add_findings(
        sid,
        [
            Finding(
                title="SQLi",
                severity=Severity.CRITICAL,
                affected_asset="https://x/?id=1",
                source_tool="sqlmap",
                cwe="CWE-89",
            )
        ],
    )
    store.finish_scan(sid)
    return store, sid


def test_analysis_column_migration_and_roundtrip(tmp_path):
    store = FindingStore(tmp_path / "m.db")
    sid = store.create_scan("e", "standard", ["x"])
    assert store.get_analysis(sid) is None
    store.set_analysis(sid, "análise xyz")
    assert store.get_analysis(sid) == "análise xyz"
    # persiste entre conexões (reabre o mesmo arquivo)
    store2 = FindingStore(tmp_path / "m.db")
    assert store2.get_analysis(sid) == "análise xyz"


def test_analyze_scan_builds_and_calls_provider():
    prov = _FakeProvider("RESUMO: ok")
    out = analyze_scan(
        [Finding(title="X", severity=Severity.HIGH, affected_asset="a", source_tool="nmap")],
        targets=["a"],
        provider=prov,
    )
    assert out == "RESUMO: ok" and prov.calls == 1


def test_analyze_and_store_persists(tmp_path):
    store, sid = _store_with_scan(tmp_path)
    prov = _FakeProvider("RESUMO: SQLi é crítico.")
    text = analyze_and_store(store, sid, provider=prov)
    assert text == "RESUMO: SQLi é crítico."
    assert store.get_analysis(sid) == text  # persistiu


def test_analyze_and_store_no_findings_returns_none(tmp_path):
    store = FindingStore(tmp_path / "empty.db")
    sid = store.create_scan("e", "standard", ["x"])
    assert analyze_and_store(store, sid, provider=_FakeProvider()) is None


def test_analyze_and_store_survives_ai_failure(tmp_path):
    store, sid = _store_with_scan(tmp_path)

    class _Boom:
        def complete(self, s, u):
            raise RuntimeError("provedor caiu")

    # não levanta — degrada para None e o scan segue
    assert analyze_and_store(store, sid, provider=_Boom()) is None
    assert store.get_analysis(sid) is None
