"""Orquestrador de scan — dirigido por perspectiva, pipeline e registry.

Coordena os plugins respeitando escopo E perspectiva: valida cada alvo antes de
executar, resolve por *capability* quais plugins rodam (via
:class:`~vulnforge.engine.registry.PluginRegistry`), executa os estágios em ordem
(plugins de um estágio em paralelo), carimba a perspectiva em cada finding,
deduplica dentro da perspectiva e — opcionalmente — pontua risco.

O Core **não muda** para adicionar um plugin: a resolução é 100% por capability +
metadados. Caso de uso da camada de aplicação (depende de portas, não de infra).
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from .risk import RiskScorer

from ..findings.dedup import deduplicate
from ..findings.schema import Finding
from ..findings.store import FindingStore
from ..perspective import Perspective, profile_for
from ..security.scope import Scope, ScopeViolation
from .base import ToolNotAvailable
from .pipeline import Stage, stages_for
from .plugin import PluginSpec
from .registry import PluginRegistry

log = logging.getLogger("vulnforge.orchestrator")

ProgressCb = Callable[[str], None]


@dataclass
class ScanReport:
    scan_id: Optional[int]
    perspective: Perspective
    findings: list[Finding] = field(default_factory=list)
    skipped_tools: list[str] = field(default_factory=list)
    stages_run: list[str] = field(default_factory=list)


class Orchestrator:
    def __init__(self, store: Optional[FindingStore] = None,
                 registry: Optional[PluginRegistry] = None,
                 risk: Optional["RiskScorer"] = None) -> None:
        self._store = store
        self._registry = registry or PluginRegistry.discover()
        self._risk = risk

    def _resolve_stage_plugins(self, stage: Stage, perspective: Perspective,
                               skipped: list[str], emit: ProgressCb) -> list[PluginSpec]:
        """Plugins de um estágio: todos que provêem alguma capability do estágio,
        suportam a perspectiva, estão habilitados e disponíveis. Decisão via
        metadados — sem ``if`` de perspectiva no meio do fluxo."""
        specs: dict[str, PluginSpec] = {}
        for cap in stage.capabilities:
            for spec in self._registry.for_capability(cap, perspective):
                specs.setdefault(spec.name, spec)  # dedupe: 1 plugin, N capabilities

        selected: list[PluginSpec] = []
        for spec in specs.values():
            if not spec.metadata.enabled_by_default:
                continue
            if not spec.available():
                if spec.name not in skipped:
                    skipped.append(spec.name)
                    reason = "degradado" if spec.degraded else "indisponível"
                    emit(f"[{spec.name}] {reason} — pulado")
                continue
            selected.append(spec)
        return selected

    def run(self, targets: list[str], *, scope: Scope,
            perspective: Optional[Perspective] = None, profile: str = "standard",
            override_perspective: bool = False,
            progress: Optional[ProgressCb] = None, **tool_opts) -> ScanReport:
        persp = perspective or scope.perspective
        persp_profile = profile_for(persp)

        # Guardrail: valida escopo E perspectiva (público×privado) ANTES de executar.
        for t in targets:
            scope.enforce(t, perspective=persp, override=override_perspective)

        # Rate limit padrão do perfil de perspectiva, se o chamador não informar.
        tool_opts.setdefault("rate_limit", persp_profile.default_rate_limit)

        stages = stages_for(persp, profile)

        def emit(msg: str) -> None:
            log.info(msg)
            if progress:
                progress(msg)

        emit(f"perspectiva={persp.value} perfil={profile} "
             f"rate_limit={tool_opts['rate_limit']} estágios={[s.name for s in stages]}")

        scan_id = None
        if self._store:
            scan_id = self._store.create_scan(scope.engagement, f"{persp.value}/{profile}", targets)

        raw: list[Finding] = []
        skipped: list[str] = []
        stages_run: list[str] = []

        for stage in stages:
            specs = self._resolve_stage_plugins(stage, persp, skipped, emit)
            if not specs:
                continue
            stages_run.append(stage.name)
            emit(f"== estágio '{stage.name}': {[s.name for s in specs]} ==")
            # plugins do mesmo estágio rodam em paralelo (respeitando rate limit).
            jobs = [(spec, target) for spec in specs for target in targets]
            max_workers = len(jobs) if stage.parallel else 1
            with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
                results = pool.map(lambda j: self._safe_scan(*j, emit=emit, **tool_opts), jobs)
                for res in results:
                    raw.extend(res)

        # carimba a perspectiva em cada finding (rastreabilidade da origem).
        for f in raw:
            f.perspective = persp

        findings = deduplicate(raw)  # dedup dentro da perspectiva (fingerprint inclui persp)

        # Risk scoring opcional (CVSS/EPSS/KEV) — só se um scorer foi injetado.
        if self._risk is not None:
            findings = self._risk.score(findings)

        findings.sort(key=lambda f: (f.risk_rank, f.severity.rank), reverse=True)

        if self._store and scan_id is not None:
            self._store.add_findings(scan_id, findings)
            self._store.finish_scan(scan_id)

        emit(f"scan concluído: {len(findings)} findings, {len(stages_run)} estágios, "
             f"{len(skipped)} plugins pulados")
        return ScanReport(scan_id=scan_id, perspective=persp, findings=findings,
                          skipped_tools=skipped, stages_run=stages_run)

    def _safe_scan(self, spec: PluginSpec, target: str, *,
                   emit: ProgressCb, **opts) -> list[Finding]:
        """Executa um plugin isolando falhas: um erro registra e segue."""
        try:
            return spec.scan(target, **opts)
        except ToolNotAvailable as exc:
            emit(f"[{spec.name}] indisponível: {exc}")
        except ScopeViolation:
            raise
        except Exception as exc:  # noqa: BLE001 — um plugin não derruba o pipeline
            emit(f"[{spec.name}] erro em {target}: {exc}")
        return []
