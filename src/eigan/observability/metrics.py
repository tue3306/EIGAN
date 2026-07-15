"""Métricas ao vivo de um scan — um assinante do event bus (§22 observabilidade).

:class:`MetricsCollector` é um ``EventSink``: assine-o no :class:`~eigan.engine.bus.EventBus`
e ele agrega, em tempo real e sem custo perceptível, contadores úteis para o
dashboard/health (§19): eventos por tipo, execuções de ferramenta por status,
descobertas e uso de tokens. É **não-levantador** por contrato (métrica nunca
derruba um scan) e thread-safe.
"""

from __future__ import annotations

import threading
from typing import Any


class MetricsCollector:
    """Acumula contadores de telemetria a partir dos eventos de um scan."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_type: dict[str, int] = {}
        self._tool_status: dict[str, int] = {}
        self._discoveries = 0
        self._tokens = 0
        self._ai_calls = 0

    def emit(self, event: dict[str, Any]) -> None:
        try:
            etype = str(event.get("type", ""))
            with self._lock:
                self._by_type[etype] = self._by_type.get(etype, 0) + 1
                if etype == "tool_execution":
                    status = str(event.get("status", ""))
                    self._tool_status[status] = self._tool_status.get(status, 0) + 1
                elif etype == "discovery":
                    self._discoveries += 1
                elif etype == "token_usage":
                    usage = event.get("usage") or {}
                    self._tokens += _int(usage.get("total_tokens"))
                    self._ai_calls += _int(usage.get("calls"))
        except Exception:  # noqa: BLE001 — métricas são best-effort, nunca levantam
            return None

    def snapshot(self) -> dict[str, Any]:
        """Fotografia dos contadores (para o dashboard/health/relatório)."""
        with self._lock:
            return {
                "events": dict(self._by_type),
                "events_total": sum(self._by_type.values()),
                "tool_executions": dict(self._tool_status),
                "discoveries": self._discoveries,
                "tokens": self._tokens,
                "ai_calls": self._ai_calls,
            }


def _int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int) and value >= 0:
        return value
    return 0
