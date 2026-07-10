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


class OpenAIProvider(_HTTPProvider):
    def _complete(self, system: str, user: str) -> str:
        data = self._post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self._credential}",
                "content-type": "application/json",
            },
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


def default_provider() -> AIProvider | None:
    """Descobre um provedor a partir do ambiente. Retorna None (sem quebrar) se
    nenhuma chave/modelo estiver configurado — o produto segue 100% sem IA.

    Prioridade: Anthropic → OpenAI → Google → Ollama. A Anthropic funciona só com
    a chave (modelo verificado por padrão); os demais exigem também
    ``<PROVIDER>_MODEL`` (anti-invenção — não fixamos um id não confirmado)."""
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if anthropic_key:
        return AnthropicProvider(
            model=os.getenv("ANTHROPIC_MODEL", _DEFAULT_ANTHROPIC_MODEL), credential=anthropic_key
        )

    openai_key, openai_model = os.getenv("OPENAI_API_KEY"), os.getenv("OPENAI_MODEL")
    if openai_key and openai_model:
        return OpenAIProvider(model=openai_model, credential=openai_key)

    google_key, google_model = os.getenv("GOOGLE_API_KEY"), os.getenv("GOOGLE_MODEL")
    if google_key and google_model:
        return GoogleProvider(model=google_model, credential=google_key)

    ollama_host, ollama_model = os.getenv("OLLAMA_HOST"), os.getenv("OLLAMA_MODEL")
    if ollama_host and ollama_model:
        return OllamaProvider(model=ollama_model, credential=ollama_host, redact_external=False)

    return None
