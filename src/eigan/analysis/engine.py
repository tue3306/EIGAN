"""Analysis Engine — a IA analisa o scan ao FINAL, automaticamente.

Distinto do enriquecimento por-finding: aqui a IA produz a INTELIGÊNCIA do scan
inteiro — resumo executivo, riscos principais, correlações entre ferramentas,
possíveis falsos-positivos e próximos passos —, rodada de forma automática quando o
scan termina (etapa "Gerar análise" do fluxo do Orchestrator). Grounded nos
findings (§3.1). Degrada com elegância: se a IA falhar, o scan NÃO quebra — apenas
fica sem análise (logada), nunca um stack trace para o usuário.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from ..ai.context import build_scan_context
from ..ai.conversation import CompletionPort, analyze
from ..findings.schema import Finding

if TYPE_CHECKING:
    from ..findings.store import FindingStore

log = logging.getLogger("eigan.analysis")


def analyze_scan(
    findings: list[Finding],
    *,
    engagement: str = "",
    targets: list[str] | None = None,
    profile: str = "",
    provider: CompletionPort | None = None,
) -> str:
    """Análise estruturada da IA sobre o conjunto de findings do scan."""
    context = build_scan_context(
        findings, engagement=engagement, targets=targets or [], profile=profile
    )
    return analyze(context, provider=provider)


def analyze_and_store(
    store: "FindingStore", scan_id: int, *, provider: CompletionPort | None = None
) -> str | None:
    """Roda a análise da IA para ``scan_id`` e persiste no store. Nunca levanta —
    retorna a análise ou ``None`` (sem findings / falha de IA logada)."""
    meta = store.get_scan(scan_id)
    if not meta:
        return None
    findings = store.get_findings(scan_id)
    if not findings:
        return None
    try:
        targets = json.loads(meta.get("targets") or "[]")
    except (json.JSONDecodeError, TypeError):
        targets = []
    try:
        text = analyze_scan(
            findings,
            engagement=meta.get("engagement", ""),
            targets=targets,
            profile=meta.get("profile", ""),
            provider=provider,
        )
    except Exception as exc:  # noqa: BLE001 — falha de IA nunca derruba o scan
        log.warning("Analysis Engine falhou para o scan %s: %s", scan_id, exc)
        return None
    if text:
        store.set_analysis(scan_id, text)
    return text
