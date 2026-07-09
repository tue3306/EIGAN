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
from abc import ABC, abstractmethod
from dataclasses import dataclass

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


def default_provider() -> AIProvider | None:
    """Descobre um provedor a partir do ambiente. Retorna None (sem quebrar) se
    nenhuma chave estiver configurada — o produto segue funcionando sem IA."""
    # A implementação concreta (chamada HTTP ao provedor) fica na infra; aqui só
    # sinalizamos ausência de chave para manter o núcleo sem dependência de rede.
    if not any(
        os.getenv(k)
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "OLLAMA_HOST")
    ):
        return None
    return None  # placeholder: adapters concretos plugam aqui (Fase 4)
