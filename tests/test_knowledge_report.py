"""Testes da base de conhecimento e do relatório determinístico (sem IA)."""

from pathlib import Path

from vulnforge.ai.provider import Enricher
from vulnforge.findings.schema import Finding, Severity
from vulnforge.knowledge.loader import KnowledgeBase
from vulnforge.report.deterministic import ReportGenerator

_KB = Path(__file__).resolve().parents[1] / "knowledge" / "skills"


def test_kb_loads_skills():
    kb = KnowledgeBase(_KB)
    assert len(kb) >= 3
    skill = kb.match(cwe="CWE-89")
    assert skill is not None
    assert "Remediation" in skill.sections


def test_deterministic_enricher_uses_skill():
    kb = KnowledgeBase(_KB)
    enr = Enricher(kb, provider=None)  # sem IA
    assert not enr.ai_enabled
    f = Finding(title="SQLi", severity=Severity.HIGH, affected_asset="h",
                source_tool="nuclei", cwe="CWE-89")
    exp = enr.explain(f)
    assert not exp.ai_generated
    assert exp.remediation  # veio da skill


def test_report_html_without_ai():
    kb = KnowledgeBase(_KB)
    gen = ReportGenerator(Enricher(kb, provider=None))
    f = Finding(title="Porta aberta", severity=Severity.INFO, affected_asset="127.0.0.1:80",
                source_tool="nmap")
    html = gen.render_html([f], engagement="lab", targets=["127.0.0.1"])
    assert "Relatório de Avaliação de Vulnerabilidades" in html
    assert "127.0.0.1:80" in html
    assert "Página" in html  # rodapé/paginacao no CSS
