"""Testes da camada de IA: redaction, grounding, parsing, seleção e fallback.

A chamada HTTP fica isolada em ``_complete``/``_post`` — o round-trip da Anthropic
é exercitado com ``httpx.MockTransport`` (sem rede). Sem chave/modelo, o produto
segue 100% determinístico (o fallback nunca depende de IA).
"""

import json

import pytest

from eigan.ai.provider import (
    AIProvider,
    AnthropicProvider,
    Enricher,
    Explanation,
    GroqProvider,
    OpenAIProvider,
    ProviderSpec,
    _build_prompts,
    _parse_explanation,
    default_provider,
    list_providers,
    redact,
    register,
)
from eigan.findings.schema import Finding, Severity
from eigan.knowledge.loader import KnowledgeBase

_AI_ENV = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "OLLAMA_HOST",
    "ANTHROPIC_MODEL",
    "OPENAI_MODEL",
    "GOOGLE_MODEL",
    "OLLAMA_MODEL",
    "GROQ_API_KEY",
    "GROQ_MODEL",
    "OPENROUTER_API_KEY",
    "OPENROUTER_MODEL",
    "TOGETHER_API_KEY",
    "TOGETHER_MODEL",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_DEPLOYMENT",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_API_VERSION",
    "EIGAN_AI_PROVIDER",
)


def _finding():
    return Finding(
        title="SQL Injection",
        severity=Severity.HIGH,
        affected_asset="http://alvo/app",
        source_tool="nuclei",
        cwe="CWE-89",
        description="Parâmetro id vulnerável.",
    )


@pytest.fixture(autouse=True)
def _clean_ai_env(monkeypatch):
    for key in _AI_ENV:
        monkeypatch.delenv(key, raising=False)


# --------------------------------------------------------------------------- #
# Redaction (§7)
# --------------------------------------------------------------------------- #
def test_redact_strips_secrets_and_pii():
    out = redact("password: hunter2 contato ana@empresa.com chave AKIAABCDEFGHIJKLMNOP")
    assert "hunter2" not in out
    assert "ana@empresa.com" not in out
    assert "AKIAABCDEFGHIJKLMNOP" not in out
    assert "[REDACTED]" in out


def test_build_prompts_grounds_on_finding_and_context():
    system, user = _build_prompts(_finding(), "remediação da skill CWE-89")
    assert "CWE-89" in user
    assert "remediação da skill" in user
    assert "NUNCA invente" in system  # instrução anti-invenção no prompt


def test_parse_explanation_splits_sections():
    exp = _parse_explanation("EXPLICAÇÃO: é grave\nREMEDIAÇÃO: use prepared statements", _finding())
    assert exp.ai_generated is True
    assert exp.text == "é grave"
    assert "prepared statements" in exp.remediation


# --------------------------------------------------------------------------- #
# Seleção de provedor por ambiente
# --------------------------------------------------------------------------- #
def test_default_provider_none_without_config():
    assert default_provider() is None


def test_require_provider_raises_without_config():
    # AI-native (§3.4/ADR-0012): sem provedor, recusa acionável (não None, não crash).
    from eigan.ai.provider import AIProviderRequired, require_provider

    with pytest.raises(AIProviderRequired) as exc:
        require_provider()
    assert "provedor de IA" in str(exc.value)
    assert "ollama" in str(exc.value).lower()  # mensagem aponta a opção local


def test_require_provider_returns_when_configured(monkeypatch):
    from eigan.ai.provider import require_provider

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    assert isinstance(require_provider(), AnthropicProvider)


def test_default_provider_anthropic_from_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    provider = default_provider()
    assert isinstance(provider, AnthropicProvider)
    assert provider.available() is True


def test_default_provider_openai_requires_model(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-oai")
    assert default_provider() is None  # sem OPENAI_MODEL → não fabricamos um id
    monkeypatch.setenv("OPENAI_MODEL", "algum-modelo")
    assert isinstance(default_provider(), OpenAIProvider)


# --------------------------------------------------------------------------- #
# Registro modular de provedores (§ AI Providers)
# --------------------------------------------------------------------------- #
def test_registry_lists_all_expected_providers():
    names = {s.name for s in list_providers()}
    # o pedido: independência de provedor único, extensível.
    assert {
        "anthropic",
        "openai",
        "gemini",
        "openrouter",
        "groq",
        "together",
        "azure",
        "ollama",
    } <= names


def test_explicit_provider_selection_via_env(monkeypatch):
    # o usuário escolhe o provedor por env, mesmo com outra chave presente.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")  # anthropic tem prioridade…
    monkeypatch.setenv("GROQ_API_KEY", "gsk-x")
    monkeypatch.setenv("GROQ_MODEL", "algum-modelo")
    monkeypatch.setenv("EIGAN_AI_PROVIDER", "groq")  # …mas a escolha explícita vence
    assert isinstance(default_provider(), GroqProvider)


def test_groq_uses_confirmed_openai_compatible_base_url():
    httpx = pytest.importorskip("httpx")
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = GroqProvider(model="algum-modelo", credential="gsk", client=client)
    assert provider.complete("s", "u") == "ok"
    assert captured["url"] == "https://api.groq.com/openai/v1/chat/completions"


def test_register_new_provider_without_touching_core():
    # adicionar provedor = registrar um ProviderSpec (interface padrão), sem
    # alterar o resto do código — exatamente o requisito de modularidade.
    register(
        ProviderSpec(
            "meu_provedor",
            "Provedor Custom",
            OpenAIProvider,
            "MEUPROV_API_KEY",
            "MEUPROV_MODEL",
            base_url_env="MEUPROV_BASE_URL",
            default_base_url="https://exemplo/v1",
        )
    )
    assert any(s.name == "meu_provedor" for s in list_providers())


# --------------------------------------------------------------------------- #
# Round-trip Anthropic (MockTransport) + redaction no envio
# --------------------------------------------------------------------------- #
def test_anthropic_roundtrip_and_grounding():
    httpx = pytest.importorskip("httpx")
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "EXPLICAÇÃO: risco alto\nREMEDIAÇÃO: filtre"}]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = AnthropicProvider(model="claude-opus-4-8", credential="sk-test", client=client)
    exp = provider.explain(_finding(), "contexto")
    assert exp.ai_generated is True
    assert "risco alto" in exp.text and "filtre" in exp.remediation
    assert captured["url"] == "https://api.anthropic.com/v1/messages"
    assert captured["headers"]["x-api-key"] == "sk-test"
    assert captured["headers"]["anthropic-version"] == "2023-06-01"
    assert captured["body"]["model"] == "claude-opus-4-8"


def test_external_provider_redacts_before_send():
    httpx = pytest.importorskip("httpx")
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = AnthropicProvider(model="claude-opus-4-8", credential="k", client=client)
    finding = _finding()
    finding.description = "senha encontrada password: s3cr3t no log"
    provider.explain(finding, "")
    sent = captured["body"]["messages"][0]["content"]
    assert "s3cr3t" not in sent and "[REDACTED]" in sent


# --------------------------------------------------------------------------- #
# Fallback determinístico intacto
# --------------------------------------------------------------------------- #
class _Boom(AIProvider):
    def available(self) -> bool:
        return True

    def explain(self, finding, context) -> Explanation:
        raise RuntimeError("sem rede")


def test_enricher_falls_back_when_provider_errors(tmp_path):
    enricher = Enricher(KnowledgeBase(tmp_path), provider=_Boom())
    exp = enricher.explain(_finding())
    assert exp.ai_generated is False  # caiu para o determinístico, sem quebrar
    assert exp.text


def test_enricher_without_provider_is_deterministic(tmp_path):
    enricher = Enricher(KnowledgeBase(tmp_path), provider=None)
    assert enricher.ai_enabled is False
    assert enricher.explain(_finding()).ai_generated is False
