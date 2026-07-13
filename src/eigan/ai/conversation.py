"""Conversation Engine — a IA responde perguntas sobre um scan, com grounding.

Amarra Context Manager + Prompt Manager + provedor: monta o contexto factual do
scan, aplica o prompt certo e chama a IA. O operador pode perguntar durante ou
depois da investigação ("explique essa vuln", "tem exploit público?", "como
corrijo?"). A IA responde SÓ com base no que foi coletado (§3.1).

AI-native: sem provedor, levanta :class:`AIProviderRequired` (o endpoint mapeia
para HTTP 428) — não há "chat sem IA".
"""

from __future__ import annotations

from typing import Protocol

from . import prompts
from .provider import AIProviderRequired, require_provider


class CompletionPort(Protocol):
    def complete(self, system: str, user: str) -> str: ...


def _provider(explicit: CompletionPort | None) -> CompletionPort:
    if explicit is not None:
        return explicit
    prov = require_provider()
    if not hasattr(prov, "complete"):  # pragma: no cover - defensivo
        raise AIProviderRequired("provedor de IA não suporta conversação")
    return prov  # type: ignore[return-value]


def answer_question(
    context: str,
    question: str,
    *,
    history: list[dict] | None = None,
    provider: CompletionPort | None = None,
) -> str:
    """Resposta da IA à ``question`` sobre o scan descrito em ``context``."""
    q = (question or "").strip()
    if not q:
        return "Faça uma pergunta sobre o scan (ex.: 'qual o risco mais crítico?')."
    prov = _provider(provider)
    user = prompts.chat_user(context, q, history)
    out = prov.complete(prompts.CHAT_SYSTEM, user).strip()
    return out or "Não consegui gerar uma resposta agora — tente reformular a pergunta."


def analyze(context: str, *, provider: CompletionPort | None = None) -> str:
    """Análise estruturada do scan (resumo/riscos/correlações/próximos passos)."""
    prov = _provider(provider)
    out = prov.complete(prompts.ANALYSIS_SYSTEM, prompts.analysis_user(context)).strip()
    return out
