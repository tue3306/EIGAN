"""Testes de exporters (JSON/CSV/SARIF) e do relatório Executivo — todos sem IA."""

import json
from pathlib import Path

from eigan.ai.provider import Enricher
from eigan.findings.schema import CVSS, Finding, RiskScore, Severity
from eigan.knowledge.loader import KnowledgeBase
from eigan.report import exporters
from eigan.report.deterministic import ReportGenerator

_KB = Path(__file__).resolve().parents[1] / "knowledge" / "skills"


def _findings():
    f1 = Finding(
        title="SQLi",
        severity=Severity.HIGH,
        affected_asset="http://h/app",
        source_tool="nuclei",
        cwe="CWE-89",
        owasp="A03:2021",
        attack_technique="T1190",
        cvss=CVSS(version="3.1", score=8.8),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"],
    )
    f1.risk = RiskScore(
        score=96.0,
        epss=0.9,
        epss_verified=True,
        kev=True,
        kev_verified=True,
        provenance={"kev": "CISA KEV 2026-07-07"},
    )
    f2 = Finding(
        title="Porta aberta 80",
        severity=Severity.INFO,
        affected_asset="10.0.0.5:80",
        source_tool="nmap",
    )
    return [f1, f2]


def test_json_export_roundtrips():
    out = exporters.to_json(_findings(), meta={"engagement": "lab"})
    data = json.loads(out)
    assert data["count"] == 2
    assert data["summary"]["high"] == 1
    assert data["findings"][0]["cwe"] == "CWE-89"
    assert data["meta"]["engagement"] == "lab"


def test_csv_export_has_header_and_rows():
    out = exporters.to_csv(_findings())
    lines = out.strip().splitlines()
    assert lines[0].startswith("title,severity,risk_score")
    assert len(lines) == 3  # header + 2 findings
    assert "CWE-89" in out and "10.0.0.5:80" in out


def test_sarif_is_valid_2_1_0():
    out = exporters.to_sarif(_findings(), tool_version="0.2.0")
    log = json.loads(out)
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "EIGAN"
    levels = {r["level"] for r in run["results"]}
    assert levels <= {"error", "warning", "note"}
    # finding HIGH -> error; INFO -> note
    assert "error" in levels and "note" in levels


def test_executive_report_without_ai():
    gen = ReportGenerator(
        Enricher(KnowledgeBase(_KB), provider=None),
        feeds_meta={"kev": "2026-07-07", "epss": "2026-07-08"},
    )
    html = gen.render_html(_findings(), engagement="lab", targets=["10.0.0.5"], style="executive")
    assert "Relatório Executivo de Riscos" in html
    assert "Riscos prioritários" in html
    assert "CISA KEV" in html  # KEV verificado aparece
    assert "2026-07-07" in html  # provenance do feed
    assert "MITRE ATT&amp;CK" in html  # seção Purple
    assert "T1190" in html and "Initial Access" in html  # técnica mapeada


def test_executive_marks_unverified_when_no_feed():
    gen = ReportGenerator(Enricher(KnowledgeBase(_KB), provider=None))  # sem feeds_meta
    f = Finding(title="X", severity=Severity.MEDIUM, affected_asset="h", source_tool="nuclei")
    html = gen.render_html([f], engagement="lab", targets=["h"], style="executive")
    assert "UNVERIFIED" in html
