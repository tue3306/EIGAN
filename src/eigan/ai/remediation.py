"""Plano de Remediação por IA — "o que arrumar e como", priorizado e grounded.

Distinto de :mod:`eigan.report.remediation` (artefatos Ansible determinísticos):
aqui a IA lê o contexto do scan e produz um plano ACIONÁVEL por finding/ativo,
priorizado por risco (o que corrigir + como corrigir + prioridade + esforço). É
uma única chamada de IA — saída JSON estruturada validada (Pydantic v2), com
fallback textual se o modelo não devolver JSON no schema.

Grounding (§3.1): só usa os findings do scan como contexto; nunca inventa CVE,
versão, score ou exploit. AI-native (§3.4): sem provedor, levanta
:class:`AIProviderRequired` (o endpoint mapeia para HTTP 428) — não há plano
"sem IA" (o relatório determinístico tem seu próprio caminho por KB).
"""

from __future__ import annotations

import json

from pydantic import BaseModel, Field, ValidationError

from . import prompts
from .conversation import CompletionPort, _provider


class RemediationItem(BaseModel):
    """Um item acionável do plano de remediação (o que + como)."""

    title: str = ""
    asset: str = ""
    severity: str = ""
    what: str = ""  # o que precisa ser corrigido
    how: str = ""  # como corrigir (passos concretos)
    priority: str = ""  # P1..P4
    effort: str = ""  # baixo | médio | alto


class RemediationPlan(BaseModel):
    """Plano de remediação priorizado, gerado pela IA (marcado ``ai_generated``)."""

    items: list[RemediationItem] = Field(default_factory=list)
    summary: str = ""
    text: str = ""  # fallback: resposta crua quando não veio JSON no schema
    ai_generated: bool = True

    def is_empty(self) -> bool:
        return not self.items and not self.summary.strip() and not self.text.strip()


def _extract_json(raw: str) -> str | None:
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    return raw[start : end + 1]


class _PlanOut(BaseModel):
    items: list[RemediationItem] = Field(default_factory=list)
    summary: str = ""


def _complete(prov: CompletionPort, system: str, user: str) -> str:
    """Chama o provedor pedindo JSON quando suportado; degrada para texto puro.

    Os provedores concretos aceitam ``json_mode`` (saída estruturada garantida);
    fakes/portas antigas que não aceitam o kwarg caem no ``complete`` simples."""
    try:
        return prov.complete(system, user, json_mode=True)  # type: ignore[call-arg]
    except TypeError:
        return prov.complete(system, user)


def remediation_plan(context: str, *, provider: CompletionPort | None = None) -> RemediationPlan:
    """Gera o plano de remediação priorizado a partir do contexto do scan.

    Tenta saída estruturada (JSON) e valida; se o modelo divergir do schema,
    devolve o texto cru em ``text`` (o dashboard/relatório ainda o exibem)."""
    prov = _provider(provider)
    raw = _complete(prov, prompts.REMEDIATION_SYSTEM, prompts.remediation_user(context)).strip()
    if not raw:
        return RemediationPlan(ai_generated=True)
    blob = _extract_json(raw)
    if blob is not None:
        try:
            out = _PlanOut.model_validate_json(blob)
            return RemediationPlan(items=out.items, summary=out.summary.strip(), ai_generated=True)
        except (ValidationError, ValueError):
            pass
    # fallback: não veio JSON no schema — preserva o texto para não perder o valor.
    return RemediationPlan(text=raw, ai_generated=True)


def plan_to_json(plan: RemediationPlan) -> str:
    """Serializa o plano para persistência (store) — determinístico."""
    return json.dumps(plan.model_dump(), ensure_ascii=False)


def plan_from_json(blob: str | None) -> RemediationPlan | None:
    """Reidrata o plano persistido; ``None`` se vazio/ausente/corrompido."""
    if not blob:
        return None
    try:
        plan = RemediationPlan.model_validate_json(blob)
    except (ValidationError, ValueError):
        return None
    return None if plan.is_empty() else plan
