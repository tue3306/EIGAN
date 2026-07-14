"""Blue Engine — run_log_analysis: detecção → persistência → IA (análise/remediação).

Usa o registry real (log-analysis é um plugin real) + store em memória + provedor
fake (sem rede). §14: hermeticamente local."""

from __future__ import annotations

from eigan.engine.blue import run_log_analysis
from eigan.engine.registry import PluginRegistry
from eigan.findings.store import FindingStore

_AUTH = "\n".join(
    [f"sshd[{i}]: Failed password for root from 203.0.113.9 port 5{i} ssh2" for i in range(6)]
    + ["sshd[9]: Accepted password for root from 203.0.113.9 port 6000 ssh2"]
)

_REM_JSON = '{"items":[{"title":"Bloquear IP","what":"x","how":"y","priority":"P1"}],"summary":"s"}'


class _FakeProv:
    def complete(self, system: str, user: str, json_mode: bool = False) -> str:
        return _REM_JSON if json_mode else "RESUMO: força-bruta detectada."


def _log(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text(_AUTH)
    return str(p)


def test_blue_detects_and_persists_without_ai(tmp_path):
    store = FindingStore(":memory:")
    report = run_log_analysis(
        [_log(tmp_path)], registry=PluginRegistry.discover(), store=store, provider=None
    )
    assert report.scan_id is not None
    assert len(report.findings) == 1
    assert report.findings[0].attack_technique == "T1110"
    assert report.findings[0].perspective.value == "internal"  # Blue = inside-out
    # persistido no store (aparece no dashboard/relatórios)
    assert len(store.get_findings(report.scan_id)) == 1
    assert report.ai_used is False
    store.close()


def test_blue_runs_ai_analysis_and_remediation(tmp_path):
    store = FindingStore(":memory:")
    report = run_log_analysis(
        [_log(tmp_path)],
        registry=PluginRegistry.discover(),
        store=store,
        provider=_FakeProv(),
    )
    assert report.ai_used is True
    assert "força-bruta" in report.analysis
    assert report.remediation_generated is True
    assert store.get_analysis(report.scan_id)
    assert store.get_remediation(report.scan_id)
    store.close()


def test_blue_no_findings_skips_ai(tmp_path):
    empty = tmp_path / "quiet.log"
    empty.write_text("nada de interessante aqui\noutra linha\n")
    store = FindingStore(":memory:")
    report = run_log_analysis(
        [str(empty)], registry=PluginRegistry.discover(), store=store, provider=_FakeProv()
    )
    assert report.findings == []
    assert report.ai_used is False
    assert store.get_analysis(report.scan_id) is None
    store.close()
