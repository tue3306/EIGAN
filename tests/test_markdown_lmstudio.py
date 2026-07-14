"""Testes do relatório Markdown e do provedor LM Studio."""

from eigan.ai.provider import PROVIDERS, OpenAIProvider
from eigan.findings.schema import Finding, Severity
from eigan.report.markdown import render_markdown


def test_markdown_has_professional_sections_and_ai_analysis():
    md = render_markdown(
        [
            Finding(
                title="SQLi",
                severity=Severity.CRITICAL,
                affected_asset="https://x/?id=1",
                source_tool="sqlmap",
                cwe="CWE-89",
            )
        ],
        engagement="demo",
        targets=["x"],
        scan_type="unified/standard",
        ai_analysis="RESUMO: risco alto.",
        tool_version="0.0.0",
    )
    for section in (
        "# Relatório EIGAN",
        "## Sumário executivo",
        "## Análise da IA",
        "## Escopo",
        "## Ferramentas utilizadas",
        "## Vulnerabilidades e resultados",
        "## Conclusão",
    ):
        assert section in md, section
    assert "RESUMO: risco alto." in md
    assert "sqlmap" in md and "CWE-89" in md


def test_markdown_escapes_pipe_in_title():
    md = render_markdown(
        [Finding(title="a|b", severity=Severity.LOW, affected_asset="x", source_tool="nmap")],
        targets=["x"],
    )
    assert "a\\|b" in md  # não quebra a tabela markdown


def test_lmstudio_registered_and_local_openai_compat():
    spec = PROVIDERS["lmstudio"]
    assert spec.provider_cls is OpenAIProvider  # usa max_completion_tokens
    assert spec.external is False  # local: sem redaction
    # credencial default (servidor local aceita qualquer) — não exige chave do env
    assert spec.credential() == "lm-studio"


def test_lmstudio_configures_with_model(monkeypatch):
    monkeypatch.delenv("LMSTUDIO_API_KEY", raising=False)
    monkeypatch.setenv("LMSTUDIO_MODEL", "qwen2.5-coder")
    spec = PROVIDERS["lmstudio"]
    assert spec.configured() is True
    assert spec.model() == "qwen2.5-coder"


def test_lmstudio_not_configured_without_model(monkeypatch):
    monkeypatch.delenv("LMSTUDIO_API_KEY", raising=False)
    monkeypatch.delenv("LMSTUDIO_MODEL", raising=False)
    assert PROVIDERS["lmstudio"].configured() is False
