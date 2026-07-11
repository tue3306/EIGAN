"""Camada de IA opcional com fallback determinístico.

Princípio (CLAUDE.md §3.3/§7): a IA NUNCA é dependência de função básica. Toda
função de enriquecimento tem um caminho determinístico equivalente que roda sem
nenhuma chave de API, alimentado pela base de conhecimento.

A IA apenas *lê e explica* findings já produzidos pelo engine — nunca escaneia
nem afirma CVE/versão fora das evidências (grounding). Toda saída de IA é
marcada ``ai_generated=True``.
"""

from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..findings.schema import Finding
from ..knowledge.loader import KnowledgeBase


@dataclass
class Explanation:
    text: str
    remediation: str
    ai_generated: bool


class AIProvider(ABC):
    """Porta multi-provedor. Implementações concretas (Anthropic/OpenAI/Google/
    Ollama) vivem na infra e são plugadas via config/ai.yaml + env."""

    @abstractmethod
    def available(self) -> bool: ...

    @abstractmethod
    def explain(self, finding: Finding, context: str) -> Explanation: ...


class DeterministicEnricher:
    """Fallback sem IA: monta explicação e remediação a partir da base de
    conhecimento (skills) casada por CWE/OWASP. Este é o caminho *default* e o
    que garante que o produto é 100% utilizável offline."""

    def __init__(self, kb: KnowledgeBase) -> None:
        self._kb = kb

    def explain(self, finding: Finding) -> Explanation:
        skill = self._kb.match(cwe=finding.cwe, owasp=finding.owasp)
        if skill:
            explanation = skill.section("When to Use") or skill.description
            remediation = skill.section("Remediation") or "Consulte as referências do finding."
            body = (
                f"{finding.description}\n\n{explanation}".strip()
                if finding.description
                else explanation
            )
            return Explanation(text=body, remediation=remediation, ai_generated=False)

        # sem skill correspondente: texto determinístico genérico a partir dos campos
        text = finding.description or (
            f"Finding '{finding.title}' de severidade {finding.severity.value} "
            f"no ativo {finding.affected_asset}, reportado por {finding.source_tool}."
        )
        remediation = (
            "Sem playbook específico na base de conhecimento. "
            "Revise as referências e aplique o princípio do menor privilégio."
        )
        return Explanation(text=text, remediation=remediation, ai_generated=False)


class Enricher:
    """Fachada: usa IA se disponível, senão cai para o determinístico.

    Nunca falha por ausência de chave — degrada graciosamente.
    """

    def __init__(self, kb: KnowledgeBase, provider: AIProvider | None = None) -> None:
        self._fallback = DeterministicEnricher(kb)
        self._kb = kb
        self._provider = provider if (provider and provider.available()) else None

    @property
    def ai_enabled(self) -> bool:
        return self._provider is not None

    def explain(self, finding: Finding) -> Explanation:
        if self._provider is None:
            return self._fallback.explain(finding)
        # grounding: entrega apenas a skill relevante como contexto
        skill = self._kb.match(cwe=finding.cwe, owasp=finding.owasp)
        context = (skill.section("Remediation") if skill else "") or finding.description
        try:
            return self._provider.explain(finding, context)
        except Exception:  # noqa: BLE001 — qualquer falha de IA cai para determinístico
            return self._fallback.explain(finding)


# --------------------------------------------------------------------------- #
# Adapters concretos multi-provedor (via httpx, dependência do extra [ai]).
#
# Grounding (§7): só enviamos as evidências do finding + a skill relevante como
# contexto — nunca pedimos ao modelo para inventar CVE/versão. Redaction remove
# segredos/PII antes de sair para provedor EXTERNO (Ollama é local → sem
# redaction). Toda saída é marcada ai_generated=True. Qualquer falha de rede/
# parse propaga e o Enricher cai para o determinístico (fallback intacto).
#
# Model id da Anthropic verificado (claude-api skill); demais provedores exigem
# <PROVIDER>_MODEL no ambiente — anti-invenção (§3.1): não fixamos um id que não
# confirmamos. Chaves só por variável de ambiente, nunca em arquivo (§5).
# --------------------------------------------------------------------------- #
_DEFAULT_ANTHROPIC_MODEL = "claude-opus-4-8"  # verificado (claude-api skill)
_ANTHROPIC_VERSION = "2023-06-01"
_MAX_TOKENS = 1024
_TIMEOUT = 30.0

_SYSTEM_PROMPT = (
    "Você é um analista de segurança sênior. Explique o finding para uma equipe "
    "técnica e proponha remediação acionável. Use SOMENTE as evidências fornecidas; "
    "NUNCA invente CVE, versão, score ou fato que não esteja nas evidências. Responda "
    "em português, em duas seções rotuladas exatamente 'EXPLICAÇÃO:' e 'REMEDIAÇÃO:'."
)

_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),  # JWT
    re.compile(
        r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd|authorization|bearer)\b\s*[:=]\s*\S+"
    ),
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),  # e-mail (PII)
]


def redact(text: str) -> str:
    """Remove segredos/PII antes de enviar a um provedor EXTERNO (§7)."""
    out = text
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return out


def _build_prompts(finding: Finding, context: str) -> tuple[str, str]:
    lines = [
        f"Título: {finding.title}",
        f"Severidade: {finding.severity.value}",
        f"Ativo afetado: {finding.affected_asset}",
        f"Ferramenta de origem: {finding.source_tool}",
    ]
    if finding.cwe:
        lines.append(f"CWE: {finding.cwe}")
    if finding.owasp:
        lines.append(f"OWASP: {finding.owasp}")
    if finding.description:
        lines.append(f"Descrição: {finding.description}")
    if context:
        lines.append(f"\nContexto (base de conhecimento, para fundamentar):\n{context}")
    return _SYSTEM_PROMPT, "Evidências do finding:\n" + "\n".join(lines)


def _parse_explanation(raw: str, finding: Finding) -> Explanation:
    text = raw.strip()
    remediation = ""
    upper = text.upper()
    if "REMEDIAÇÃO:" in upper:
        idx = upper.index("REMEDIAÇÃO:")
        remediation = text[idx + len("REMEDIAÇÃO:") :].strip()
        text = text[:idx]
    text = re.sub(r"(?i)^\s*EXPLICAÇÃO:\s*", "", text).strip()
    if not remediation:
        remediation = "Consulte as referências do finding e aplique o menor privilégio."
    return Explanation(text=text or finding.description, remediation=remediation, ai_generated=True)


class _HTTPProvider(AIProvider):
    """Base dos provedores HTTP: constrói o prompt (grounded), redige externos,
    delega a chamada a ``_complete`` e normaliza para :class:`Explanation`."""

    def __init__(
        self,
        *,
        model: str,
        credential: str,
        redact_external: bool = True,
        timeout: float = _TIMEOUT,
        client: Any = None,
    ) -> None:
        self._model = model
        self._credential = credential
        self._redact_external = redact_external
        self._timeout = timeout
        self._client = client  # injetável para teste (httpx.Client com MockTransport)

    def available(self) -> bool:
        return bool(self._credential and self._model)

    def explain(self, finding: Finding, context: str) -> Explanation:
        system, user = _build_prompts(finding, context)
        if self._redact_external:
            user = redact(user)
        return _parse_explanation(self._complete(system, user), finding)

    def complete(self, system: str, user: str) -> str:
        """Completamento de texto genérico — porta para o Planner cognitivo
        (ADR-0007). Aplica a mesma redaction externa que ``explain`` (o prompt do
        Planner pode conter títulos/ativos de findings)."""
        return self._complete(system, redact(user) if self._redact_external else user)

    def _complete(self, system: str, user: str) -> str:  # pragma: no cover - abstrato
        raise NotImplementedError

    def _post(self, url: str, *, headers: dict[str, str], payload: dict) -> dict:
        import httpx  # import tardio: só quando a IA é usada de fato (extra [ai])

        if self._client is not None:
            resp = self._client.post(url, headers=headers, json=payload)
        else:
            resp = httpx.post(url, headers=headers, json=payload, timeout=self._timeout)
        resp.raise_for_status()
        return resp.json()


class AnthropicProvider(_HTTPProvider):
    def _complete(self, system: str, user: str) -> str:
        data = self._post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self._credential,
                "anthropic-version": _ANTHROPIC_VERSION,
                "content-type": "application/json",
            },
            payload={
                "model": self._model,
                "max_tokens": _MAX_TOKENS,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        for block in data.get("content", []):
            if block.get("type") == "text":
                return str(block.get("text", ""))
        return ""


class _OpenAICompatProvider(_HTTPProvider):
    """Base para provedores que falam o schema **OpenAI Chat Completions**.

    A maioria dos provedores modernos é compatível com a OpenAI: muda só a
    ``base_url`` e o header de auth. Assim, adicionar OpenRouter/Groq/Together é
    só declarar a URL — sem reescrever a lógica (o pedido de modularidade do
    §AI Providers). A ``base_url`` é **sobrescritível por env** para não fixarmos
    um endpoint que possa mudar (anti-invenção §3.1)."""

    default_base_url = "https://api.openai.com/v1"

    def __init__(self, *, base_url: str | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._base_url = (base_url or self.default_base_url).rstrip("/")

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._credential}",
            "content-type": "application/json",
        }

    def _complete(self, system: str, user: str) -> str:
        data = self._post(
            f"{self._base_url}/chat/completions",
            headers=self._auth_headers(),
            payload={
                "model": self._model,
                "max_tokens": _MAX_TOKENS,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        return str(data["choices"][0]["message"]["content"])


class OpenAIProvider(_OpenAICompatProvider):
    default_base_url = "https://api.openai.com/v1"


class OpenRouterProvider(_OpenAICompatProvider):
    # Confirmado na doc oficial (openrouter.ai/docs/quickstart): OpenAI-compat.
    default_base_url = "https://openrouter.ai/api/v1"


class GroqProvider(_OpenAICompatProvider):
    # Confirmado (console.groq.com/docs/openai): base OpenAI-compat.
    default_base_url = "https://api.groq.com/openai/v1"


class TogetherProvider(_OpenAICompatProvider):
    # Confirmado (docs.together.ai/docs/openai-api-compatibility).
    default_base_url = "https://api.together.xyz/v1"


class AzureOpenAIProvider(_HTTPProvider):
    """Azure OpenAI: endpoint por *resource*/*deployment* + ``api-version``.

    Difere do OpenAI padrão: auth por header ``api-key``, o "modelo" é o nome do
    **deployment**, e a URL exige a ``api-version`` (que muda — vem por env, nunca
    fixada; §3.1). Requer ``AZURE_OPENAI_ENDPOINT`` e ``AZURE_OPENAI_API_VERSION``.
    """

    def __init__(self, *, base_url: str, api_version: str | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._endpoint = base_url.rstrip("/")
        self._api_version = api_version or os.getenv("AZURE_OPENAI_API_VERSION", "")

    def available(self) -> bool:
        return bool(self._credential and self._model and self._endpoint and self._api_version)

    def _complete(self, system: str, user: str) -> str:
        url = (
            f"{self._endpoint}/openai/deployments/{self._model}"
            f"/chat/completions?api-version={self._api_version}"
        )
        data = self._post(
            url,
            headers={"api-key": self._credential, "content-type": "application/json"},
            payload={
                "max_tokens": _MAX_TOKENS,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        return str(data["choices"][0]["message"]["content"])


class GoogleProvider(_HTTPProvider):
    def _complete(self, system: str, user: str) -> str:
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self._model}:generateContent?key={self._credential}"
        )
        data = self._post(
            url,
            headers={"content-type": "application/json"},
            payload={
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"parts": [{"text": user}]}],
            },
        )
        return str(data["candidates"][0]["content"]["parts"][0]["text"])


class OllamaProvider(_HTTPProvider):
    """Modelo local (sem chave, sem redaction obrigatória — não sai da máquina)."""

    def _complete(self, system: str, user: str) -> str:
        data = self._post(
            f"{self._credential.rstrip('/')}/api/chat",
            headers={"content-type": "application/json"},
            payload={
                "model": self._model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        return str(data["message"]["content"])


# --------------------------------------------------------------------------- #
# Registro de provedores (§ AI Providers) — modular e extensível.
#
# Adicionar um novo provedor é declarativo: implemente um ``_HTTPProvider`` (ou
# reuse ``_OpenAICompatProvider``) e registre um :class:`ProviderSpec`. O resto do
# sistema (CLI, onboarding, docs, seleção) descobre o provedor pelo registro —
# nenhum outro código muda. Chaves só por variável de ambiente (§5); model id
# nunca fabricado (§3.1): só a Anthropic tem default verificado, os demais exigem
# ``<PROVIDER>_MODEL``.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ProviderSpec:
    """Descreve um provedor de IA: como construí-lo e onde ler as credenciais."""

    name: str
    label: str
    provider_cls: type[_HTTPProvider]
    key_env: str  # env com a credencial (ou host, no Ollama)
    model_env: str  # env com o id do modelo/deployment
    external: bool = True  # True → redaction antes de enviar
    default_model: str | None = None  # só onde o id é verificado (Anthropic)
    base_url_env: str | None = None  # env para sobrescrever o endpoint
    default_base_url: str | None = None
    scan_fit: str = ""  # nota de adequação ao projeto (docs/onboarding)

    def credential(self) -> str | None:
        return os.getenv(self.key_env)

    def model(self) -> str | None:
        return os.getenv(self.model_env) or self.default_model

    def configured(self) -> bool:
        """True se dá para instanciar (credencial + modelo + endpoint, se exigido)."""
        if not self.credential() or not self.model():
            return False
        if self.base_url_env is not None and not (
            os.getenv(self.base_url_env) or self.default_base_url
        ):
            return False
        return True

    def build(self, *, client: Any = None) -> _HTTPProvider | None:
        if not self.configured():
            return None
        kwargs: dict[str, Any] = {
            "model": self.model(),
            "credential": self.credential(),
            "redact_external": self.external,
            "client": client,
        }
        if self.base_url_env is not None:
            kwargs["base_url"] = os.getenv(self.base_url_env) or self.default_base_url
        provider = self.provider_cls(**kwargs)
        # Só devolve um provedor **utilizável**: alguns exigem mais que credencial+
        # modelo (ex.: Azure precisa de api_version). Assim o gate AI-native
        # (require_provider) nunca aprova um provedor meio-configurado.
        return provider if provider.available() else None


PROVIDERS: dict[str, ProviderSpec] = {}
# Ordem de auto-detecção quando o usuário não escolhe explicitamente.
_PRIORITY = ["anthropic", "openai", "gemini", "openrouter", "groq", "together", "azure", "ollama"]


def register(spec: ProviderSpec) -> None:
    """Registra (ou substitui) um provedor pelo nome. Ponto de extensão único."""
    PROVIDERS[spec.name] = spec


def list_providers() -> list[ProviderSpec]:
    """Todos os provedores registrados, na ordem de prioridade conhecida."""
    known = [PROVIDERS[n] for n in _PRIORITY if n in PROVIDERS]
    extra = [s for n, s in PROVIDERS.items() if n not in _PRIORITY]
    return known + extra


for _spec in (
    ProviderSpec(
        "anthropic",
        "Anthropic (Claude)",
        AnthropicProvider,
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_MODEL",
        default_model=_DEFAULT_ANTHROPIC_MODEL,
        scan_fit="Recomendado: melhor raciocínio de planejamento/narrativa; funciona só com a chave.",
    ),
    ProviderSpec(
        "openai",
        "OpenAI (GPT)",
        OpenAIProvider,
        "OPENAI_API_KEY",
        "OPENAI_MODEL",
        base_url_env="OPENAI_BASE_URL",
        default_base_url="https://api.openai.com/v1",
        scan_fit="Forte em análise e tool-calling; exige OPENAI_MODEL.",
    ),
    ProviderSpec(
        "gemini",
        "Google Gemini",
        GoogleProvider,
        "GOOGLE_API_KEY",
        "GOOGLE_MODEL",
        scan_fit="Bom custo/contexto longo; exige GOOGLE_MODEL.",
    ),
    ProviderSpec(
        "openrouter",
        "OpenRouter (multi-modelo)",
        OpenRouterProvider,
        "OPENROUTER_API_KEY",
        "OPENROUTER_MODEL",
        base_url_env="OPENROUTER_BASE_URL",
        default_base_url="https://openrouter.ai/api/v1",
        scan_fit="Um gateway p/ 300+ modelos: troque de modelo sem trocar de conta.",
    ),
    ProviderSpec(
        "groq",
        "Groq (baixa latência)",
        GroqProvider,
        "GROQ_API_KEY",
        "GROQ_MODEL",
        base_url_env="GROQ_BASE_URL",
        default_base_url="https://api.groq.com/openai/v1",
        scan_fit="Inferência muito rápida/barata: ideal p/ triagem e classificação.",
    ),
    ProviderSpec(
        "together",
        "Together AI",
        TogetherProvider,
        "TOGETHER_API_KEY",
        "TOGETHER_MODEL",
        base_url_env="TOGETHER_BASE_URL",
        default_base_url="https://api.together.xyz/v1",
        scan_fit="Modelos open-weight hospedados; bom p/ custo previsível.",
    ),
    ProviderSpec(
        "azure",
        "Azure OpenAI",
        AzureOpenAIProvider,
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_DEPLOYMENT",
        base_url_env="AZURE_OPENAI_ENDPOINT",
        scan_fit="Para empresas em Azure com governança/residência de dados.",
    ),
    ProviderSpec(
        "ollama",
        "Ollama (local, sem chave)",
        OllamaProvider,
        "OLLAMA_HOST",
        "OLLAMA_MODEL",
        external=False,
        scan_fit="Roda 100% local: nada sai da máquina (sem redaction externa). Privacidade máxima.",
    ),
):
    register(_spec)


def _config_default_provider() -> str | None:
    """Lê ``default:`` de ``config/ai.yaml`` (se existir) — seleção sem env."""
    path = Path("config") / "ai.yaml"
    if not path.is_file():
        return None
    try:
        import yaml

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 — config quebrada nunca derruba o produto
        return None
    val = data.get("default") or data.get("provider")
    return str(val).strip().lower() if val else None


def default_provider(*, client: Any = None) -> AIProvider | None:
    """Resolve um provedor a partir de env/config. None se nada estiver
    configurado (use :func:`require_provider` quando a IA for obrigatória).

    Seleção: ``EIGAN_AI_PROVIDER`` (ou ``default:`` em ``config/ai.yaml``) escolhe
    explicitamente; senão auto-detecta na ordem de prioridade. Ollama é local (sem
    redaction); os externos exigem ``<PROVIDER>_MODEL`` (não fixamos id — §3.1)."""
    chosen = (os.getenv("EIGAN_AI_PROVIDER") or _config_default_provider() or "").strip().lower()
    if chosen:
        spec = PROVIDERS.get(chosen)
        return spec.build(client=client) if spec else None
    for spec in list_providers():
        provider = spec.build(client=client)
        if provider is not None:
            return provider
    return None


class AIProviderRequired(RuntimeError):
    """EIGAN é AI-native: sem provedor de IA configurado, não há scan (ADR-0012).

    Erro **acionável** (não é bug): diz exatamente como configurar um provedor.
    """


_NO_PROVIDER_MSG = (
    "EIGAN é um agente de IA — nenhum scan roda sem um provedor de IA configurado.\n"
    "Configure um (a chave vai para .env, fora do git, chmod 600):\n"
    "  • Fácil:  python3 eigan.py  →  Configuração  →  escolher provedor + colar a chave\n"
    "  • Manual: export EIGAN_AI_PROVIDER=<anthropic|openai|gemini|openrouter|groq|together|azure|ollama>\n"
    "            export <PROVIDER>_API_KEY=...   (e <PROVIDER>_MODEL, exceto Anthropic)\n"
    "  • Local:  Ollama (sem chave, sem custo, offline):\n"
    "            export EIGAN_AI_PROVIDER=ollama OLLAMA_HOST=http://localhost:11434 OLLAMA_MODEL=<modelo>\n"
    "Guia completo: docs/ai-providers.md"
)


def require_provider(*, client: Any = None) -> AIProvider:
    """Retorna o provedor de IA ativo ou levanta :class:`AIProviderRequired`.

    É o **gate AI-native** (§3.4/ADR-0012): os pontos de entrada de execução de
    scan chamam isto antes de rodar qualquer coisa — sem provedor, recusa com um
    erro acionável, nunca um stack trace."""
    provider = default_provider(client=client)
    if provider is None:
        raise AIProviderRequired(_NO_PROVIDER_MSG)
    return provider
