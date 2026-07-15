"""Testes do Conversation Engine + Context Manager (com provedor fake, sem rede)."""

from eigan.ai import prompts
from eigan.ai.context import build_scan_context, severity_counts
from eigan.ai.conversation import analyze, answer_question
from eigan.findings.schema import Confidence, Finding, Severity


class _FakeProvider:
    def __init__(self, reply: str = "resposta da IA") -> None:
        self.reply = reply
        self.last_system = ""
        self.last_user = ""

    def complete(self, system: str, user: str) -> str:
        self.last_system, self.last_user = system, user
        return self.reply


def _findings() -> list[Finding]:
    return [
        Finding(
            title="Injeção SQL confirmada",
            severity=Severity.CRITICAL,
            affected_asset="https://x/item?id=1",
            source_tool="sqlmap",
            cwe="CWE-89",
            confidence=Confidence.CONFIRMED,
        ),
        Finding(
            title="Web vivo",
            severity=Severity.INFO,
            affected_asset="https://x/",
            source_tool="httpx",
        ),
    ]


def test_context_lists_findings_and_tools():
    ctx = build_scan_context(_findings(), targets=["x"], profile="standard")
    assert "sqlmap" in ctx and "httpx" in ctx
    assert "Injeção SQL" in ctx
    assert "CWE CWE-89" in ctx
    # o crítico aparece antes do info (ordenado por risco)
    assert ctx.index("Injeção SQL") < ctx.index("Web vivo")


def test_context_empty_findings():
    assert "sem findings" in build_scan_context([], targets=["x"]).lower()


def test_severity_counts():
    c = severity_counts(_findings())
    assert c["critical"] == 1 and c["info"] == 1


def test_answer_question_uses_provider_and_context():
    prov = _FakeProvider("O SQLi é o mais crítico.")
    ctx = build_scan_context(_findings(), targets=["x"])
    out = answer_question(ctx, "qual o risco?", provider=prov)
    assert out == "O SQLi é o mais crítico."
    assert "CONTEXTO DO SCAN" in prov.last_user
    assert "qual o risco?" in prov.last_user
    assert prov.last_system == prompts.CHAT_SYSTEM


def test_answer_empty_question_short_circuits():
    prov = _FakeProvider()
    out = answer_question("ctx", "   ", provider=prov)
    assert "pergunta" in out.lower()
    assert prov.last_user == ""  # nem chamou o provedor


def test_history_is_included():
    prov = _FakeProvider()
    hist = [{"role": "user", "content": "oi"}, {"role": "assistant", "content": "olá"}]
    answer_question("ctx", "e agora?", history=hist, provider=prov)
    assert "CONVERSA ANTERIOR" in prov.last_user and "olá" in prov.last_user


def test_analyze_uses_analysis_prompt():
    prov = _FakeProvider("RESUMO: ok")
    out = analyze(build_scan_context(_findings(), targets=["x"]), provider=prov)
    assert out == "RESUMO: ok"
    assert prov.last_system == prompts.ANALYSIS_SYSTEM
