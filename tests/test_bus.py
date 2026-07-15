"""Testes do Event Bus (§9/§13) e do MetricsCollector (§22).

Cobrem: fan-out para N assinantes, filtro por tipo, ordem de entrega, e a
semântica de erro que preserva o cancelamento cooperativo (o bus NÃO engole
exceções). E o coletor de métricas agregando eventos reais.
"""

from __future__ import annotations

import pytest

from eigan.engine import events as ev
from eigan.engine.bus import EventBus
from eigan.observability.metrics import MetricsCollector


class _Recorder:
    def __init__(self) -> None:
        self.seen: list[dict] = []

    def emit(self, event: dict) -> None:
        self.seen.append(event)


class _Boom:
    """Sink que levanta — modela o cancelamento cooperativo (o _JobSink levanta)."""

    def emit(self, event: dict) -> None:
        raise RuntimeError("cancelado")


# --------------------------------------------------------------------------- #
# EventBus
# --------------------------------------------------------------------------- #
def test_bus_fans_out_to_all_subscribers():
    a, b = _Recorder(), _Recorder()
    bus = EventBus(a, b)
    assert len(bus) == 2
    bus.emit(ev.log("oi"))
    assert len(a.seen) == 1 and len(b.seen) == 1
    assert a.seen[0]["message"] == "oi"


def test_bus_filters_by_event_type():
    only_disc = _Recorder()
    everything = _Recorder()
    bus = EventBus()
    bus.subscribe(only_disc, types={"discovery"})
    bus.subscribe(everything)
    bus.emit(ev.log("ignora"))
    bus.emit(ev.tool_execution("nmap", "h", "completed"))
    assert only_disc.seen == []  # nenhum discovery ainda
    assert len(everything.seen) == 2


def test_bus_does_not_swallow_exceptions_so_cancel_still_works():
    # Se o bus engolisse, o cancelamento cooperativo (sink que levanta) quebraria.
    aux = _Recorder()
    bus = EventBus()
    bus.subscribe(aux)  # auxiliar primeiro — observa mesmo se o próximo abortar
    bus.subscribe(_Boom())  # sink primário que "cancela"
    with pytest.raises(RuntimeError, match="cancelado"):
        bus.emit(ev.log("x"))
    assert len(aux.seen) == 1  # o auxiliar viu o evento antes do abort


# --------------------------------------------------------------------------- #
# MetricsCollector (assinante do bus)
# --------------------------------------------------------------------------- #
def test_metrics_collector_aggregates_scan_events():
    m = MetricsCollector()
    bus = EventBus(m)
    from eigan.findings.schema import Finding, Severity

    f = Finding(title="x", severity=Severity.HIGH, affected_asset="h", source_tool="nmap")
    bus.emit(ev.tool_execution("nmap", "h", "in_progress"))
    bus.emit(ev.tool_execution("nmap", "h", "completed"))
    bus.emit(ev.tool_execution("nuclei", "h", "failed"))
    bus.emit(ev.discovery(f, []))
    bus.emit(ev.token_usage({"total_tokens": 15, "calls": 2}))
    bus.emit(ev.token_usage({"total_tokens": 10, "calls": 1}))
    snap = m.snapshot()
    assert snap["tool_executions"] == {"in_progress": 1, "completed": 1, "failed": 1}
    assert snap["discoveries"] == 1
    assert snap["tokens"] == 25 and snap["ai_calls"] == 3
    assert snap["events"]["tool_execution"] == 3
    assert snap["events_total"] == 6


def test_metrics_collector_never_raises_on_bad_event():
    m = MetricsCollector()
    m.emit({"type": "token_usage", "usage": {"total_tokens": "lixo"}})  # tipo errado
    m.emit({})  # sem type
    assert m.snapshot()["tokens"] == 0  # tolerou sem levantar
