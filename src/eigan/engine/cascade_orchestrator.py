"""Orquestração em cascata dirigida por descoberta (ADR-0004).

Envolve o :class:`~eigan.engine.orchestrator.Orchestrator` determinístico e
adiciona a camada de **cascata**: a cada finding produzido pelo pipeline, consulta
o :class:`~eigan.engine.cascade.CascadeGraph` para decidir — de forma pura e
justificada — quais ferramentas adicionais fazem sentido, transmite esses eventos
em tempo real (§3.3 do prompt de interface) e executa uma **segunda onda** com as
ferramentas disparadas que estão disponíveis e ainda não rodaram.

Fronteiras (CLAUDE.md):

* A IA **não** decide nem executa nada aqui: o grafo é declarativo (metadados) e
  o casamento é determinístico. A IA entra depois, só para *interpretar* findings.
* Toda execução passa pelo mesmo runner seguro (``spec.scan`` → subprocess com
  lista de argumentos, nunca ``shell=True``).
* Ferramentas sugeridas mas indisponíveis/roadmap são registradas honestamente
  como *sugeridas, não executadas* — nunca fingem ter rodado.
* Persistência num único ponto (evita scan meio-gravado): a cascata coleta tudo,
  deduplica, pontua risco e só então grava.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from ..findings.dedup import deduplicate
from ..findings.schema import Finding
from ..findings.store import FindingStore
from ..perspective import Perspective
from ..security.scope import Scope
from . import events as ev
from .cascade import CascadeGraph, CascadeTrigger
from .events import EventSink, NullSink
from .orchestrator import Orchestrator, ScanReport
from .registry import PluginRegistry
from .risk import RiskScorer

log = logging.getLogger("eigan.cascade")


def _host_of(asset: str) -> str:
    """Extrai o host de ``host:porta`` para servir de alvo na segunda onda."""
    if asset.count(":") == 1:  # host:porta (não IPv6)
        return asset.rsplit(":", 1)[0]
    return asset


@dataclass
class _Observer:
    """Ponte pipeline → cascata + streaming. Implementa :class:`ScanObserver`.

    Reage a cada lote de findings: emite ``discovery`` + ``cascade_log`` e acumula
    os disparos pendentes para a segunda onda. Não executa nada — decidir é aqui,
    executar é no orquestrador (mantém a reatividade simples e testável)."""

    graph: CascadeGraph
    sink: EventSink
    executed: set[str] = field(default_factory=set)  # ferramentas que já produziram finding
    pending: dict[str, CascadeTrigger] = field(default_factory=dict)  # tool → disparo (1º vence)

    def stage_started(self, stage: str) -> None:
        self.sink.emit(ev.phase_started(stage))

    def findings_produced(self, stage: str, findings: list[Finding]) -> None:
        for f in findings:
            self.executed.add(f.source_tool.lower())
        for f in findings:
            triggers = self.graph.triggered_by(f)
            self.sink.emit(ev.discovery(f, [t.tool for t in triggers]))
            for trig in triggers:
                self._register(trig)

    def stage_finished(self, stage: str, count: int) -> None:
        self.sink.emit(ev.phase_finished(stage, count))

    def _register(self, trig: CascadeTrigger) -> None:
        if trig.tool in self.pending or trig.tool in self.executed:
            return
        self.pending[trig.tool] = trig
        # registra a intenção; ``executed`` é decidido na hora de rodar a onda.
        self.sink.emit(
            ev.cascade_log(
                tool=trig.tool,
                reason=trig.reason,
                declared_by=trig.declared_by,
                source_asset=trig.source_finding.affected_asset,
                executed=False,
            )
        )


class CascadeOrchestrator:
    """Scan em cascata: pipeline determinístico + disparos dirigidos por descoberta."""

    def __init__(
        self,
        store: Optional[FindingStore] = None,
        registry: Optional[PluginRegistry] = None,
        risk: Optional[RiskScorer] = None,
        *,
        max_cascade_tools: int = 32,
    ) -> None:
        self._registry = registry if registry is not None else PluginRegistry.discover()
        self._store = store
        self._risk = risk
        self._graph = CascadeGraph.from_registry(self._registry)
        self._max = max_cascade_tools

    @property
    def graph(self) -> CascadeGraph:
        return self._graph

    def run(
        self,
        targets: list[str],
        *,
        scope: Scope,
        perspective: Optional[Perspective] = None,
        profile: str = "standard",
        override_perspective: bool = False,
        sink: Optional[EventSink] = None,
        **tool_opts,
    ) -> ScanReport:
        emitter: EventSink = sink if sink is not None else NullSink()
        persp = perspective or scope.perspective

        # Cria o scan já no início: a UI precisa do id para rotear os eventos.
        scan_id: Optional[int] = None
        if self._store is not None:
            scan_id = self._store.create_scan(scope.engagement, f"{persp.value}/{profile}", targets)
        emitter.emit(ev.scan_status(scan_id, "running", f"{persp.value}/{profile}"))

        observer = _Observer(graph=self._graph, sink=emitter)
        # Pipeline determinístico (store=None: a cascata persiste num único ponto).
        inner = Orchestrator(store=None, registry=self._registry, risk=None)
        report = inner.run(
            targets,
            scope=scope,
            perspective=persp,
            profile=profile,
            override_perspective=override_perspective,
            progress=lambda m: emitter.emit(ev.log(m)),
            observer=observer,
            **tool_opts,
        )

        raw = list(report.findings)
        raw.extend(
            self._second_wave(observer, scope, persp, override_perspective, emitter, tool_opts)
        )

        findings = deduplicate(raw)
        if self._risk is not None:
            findings = self._risk.score(findings)
        findings.sort(key=lambda f: (f.risk_rank, f.severity.rank), reverse=True)

        if self._store is not None and scan_id is not None:
            self._store.add_findings(scan_id, findings)
            self._store.finish_scan(scan_id)

        emitter.emit(
            ev.analysis_complete(
                {
                    "findings": len(findings),
                    "critical": sum(1 for f in findings if f.severity.value == "critical"),
                    "high": sum(1 for f in findings if f.severity.value == "high"),
                    "cascade_tools": len(observer.pending),
                    "stages": report.stages_run,
                }
            )
        )
        emitter.emit(ev.scan_status(scan_id, "completed"))

        return ScanReport(
            scan_id=scan_id,
            perspective=persp,
            findings=findings,
            skipped_tools=report.skipped_tools,
            stages_run=report.stages_run,
        )

    def _second_wave(
        self,
        observer: _Observer,
        scope: Scope,
        perspective: Perspective,
        override_perspective: bool,
        sink: EventSink,
        tool_opts: dict,
    ) -> list[Finding]:
        """Executa as ferramentas disparadas que estão disponíveis e não rodaram.

        Profundidade 1 (bounded): a segunda onda **não** dispara novas cascatas,
        evitando recursão não-limitada. Ferramentas roadmap/indisponíveis são
        registradas como sugeridas, não executadas — scaffold honesto."""
        out: list[Finding] = []
        for tool, trig in list(observer.pending.items())[: self._max]:
            spec = self._registry.get(tool)
            target = _host_of(trig.source_finding.affected_asset)
            if spec is None or not spec.available() or not spec.runs_in(perspective):
                sink.emit(
                    ev.cascade_log(
                        tool=tool,
                        reason=f"{trig.reason} — indisponível/roadmap (sugerido, não executado)",
                        declared_by=trig.declared_by,
                        source_asset=trig.source_finding.affected_asset,
                        executed=False,
                    )
                )
                continue
            try:
                scope.enforce(target, perspective=perspective, override=override_perspective)
            except Exception as exc:  # noqa: BLE001 — fora de escopo não derruba a onda
                sink.emit(
                    ev.tool_execution(tool, target, "skipped", detail=f"fora de escopo: {exc}")
                )
                continue

            sink.emit(ev.tool_execution(tool, target, "in_progress"))
            try:
                found = spec.scan(target, **tool_opts)
            except Exception as exc:  # noqa: BLE001 — um plugin não derruba o scan
                sink.emit(ev.tool_execution(tool, target, "failed", detail=str(exc)))
                continue
            for f in found:
                f.perspective = perspective
            out.extend(found)
            sink.emit(ev.tool_execution(tool, target, "completed", 100, f"{len(found)} finding(s)"))
            sink.emit(
                ev.cascade_log(
                    tool=tool,
                    reason=trig.reason,
                    declared_by=trig.declared_by,
                    source_asset=trig.source_finding.affected_asset,
                    executed=True,
                )
            )
        return out
