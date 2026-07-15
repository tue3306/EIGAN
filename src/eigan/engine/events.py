"""Eventos de progresso de scan (contrato de streaming em tempo real).

A UI (§3.3 do prompt de interface) mostra fases, descobertas e cascatas conforme
acontecem. Para isso o orquestrador emite *eventos estruturados* através de um
:class:`EventSink` — uma **porta do domínio**: o Core não conhece WebSocket nem
FastAPI, só chama ``sink.emit(evento)``. A infraestrutura (API) fornece a
implementação concreta que faz o broadcast.

Todo evento é um ``dict`` JSON-serializável com ``type`` e ``timestamp`` (UTC
ISO-8601). Os construtores abaixo são a fonte única do formato — a UI e os testes
dependem deles, não de strings soltas.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from ..findings.schema import Finding


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


@runtime_checkable
class EventSink(Protocol):
    """Porta de saída de eventos. Implementada pela infra (ex.: broadcaster WS)."""

    def emit(self, event: dict[str, Any]) -> None: ...


class NullSink:
    """Sink que descarta tudo — default quando ninguém observa (CLI, testes de core)."""

    def emit(self, event: dict[str, Any]) -> None:  # noqa: D401 - no-op
        return None


# ── construtores de evento (formato único) ──────────────────────────────────
def phase_started(phase: str, detail: str = "") -> dict[str, Any]:
    return {"type": "phase_started", "phase": phase, "detail": detail, "timestamp": _ts()}


def phase_finished(phase: str, findings: int) -> dict[str, Any]:
    return {"type": "phase_finished", "phase": phase, "findings": findings, "timestamp": _ts()}


def discovery(finding: Finding, cascade_triggered: list[str]) -> dict[str, Any]:
    return {
        "type": "discovery",
        "finding": finding.model_dump(mode="json"),
        "cascade_triggered": cascade_triggered,
        "timestamp": _ts(),
    }


def tool_execution(
    tool: str, target: str, status: str, progress: int = 0, detail: str = ""
) -> dict[str, Any]:
    """status ∈ {queued, in_progress, completed, failed, skipped}."""
    return {
        "type": "tool_execution",
        "tool": tool,
        "target": target,
        "status": status,
        "progress": progress,
        "detail": detail,
        "timestamp": _ts(),
    }


def cascade_log(
    tool: str, reason: str, declared_by: str, source_asset: str, executed: bool
) -> dict[str, Any]:
    """Registro justificado de um disparo de cascata — 'sem mágica' (§2 do prompt).

    ``executed=False`` quando a ferramenta sugerida é roadmap/indisponível: o
    disparo é honestamente registrado como *sugerido, não executado*.
    """
    return {
        "type": "cascade_log",
        "tool": tool,
        "reason": reason,
        "declared_by": declared_by,
        "source_asset": source_asset,
        "executed": executed,
        "timestamp": _ts(),
    }


def log(message: str) -> dict[str, Any]:
    return {"type": "log", "message": message, "timestamp": _ts()}


def scan_status(scan_id: int | None, status: str, detail: str = "") -> dict[str, Any]:
    """status ∈ {running, completed, failed, cancelled}."""
    return {
        "type": "scan_status",
        "scan_id": scan_id,
        "status": status,
        "detail": detail,
        "timestamp": _ts(),
    }


def analysis_complete(summary: dict[str, Any]) -> dict[str, Any]:
    return {"type": "analysis_complete", "summary": summary, "timestamp": _ts()}


def token_usage(usage: dict[str, Any], by_model: dict[str, Any] | None = None) -> dict[str, Any]:
    """Uso de tokens da IA acumulado no scan (observabilidade §22, ADR-0025).

    ``usage`` = ``{prompt_tokens, completion_tokens, total_tokens}`` + ``calls``;
    ``by_model`` mapeia ``"<provider>:<model>"`` → uso. Números **reais** do provedor
    (nunca estimados); o custo em dinheiro só aparece com preço verificado (cost.py).
    """
    return {
        "type": "token_usage",
        "usage": usage,
        "by_model": by_model or {},
        "timestamp": _ts(),
    }
