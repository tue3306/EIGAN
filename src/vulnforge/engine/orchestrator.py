"""Orquestrador de scan — dirigido por perspectiva e pipeline.

Coordena os adapters respeitando escopo E perspectiva: valida cada alvo contra a
perspectiva (público×privado) antes de executar, ativa apenas adapters
compatíveis com a perspectiva do job (via ``supported_perspectives``), roda os
estágios do pipeline em ordem (ferramentas de um mesmo estágio em paralelo),
carimba a perspectiva em cada finding e deduplica dentro da perspectiva.

Caso de uso da camada de aplicação: depende de portas (adapters, store, scope,
pipeline) e não de infra concreta.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..findings.dedup import deduplicate
from ..findings.schema import Finding
from ..findings.store import FindingStore
from ..perspective import Perspective, profile_for
from ..security.scope import Scope, ScopeViolation
from .adapters.dnsx_adapter import DnsxAdapter
from .adapters.httpx_adapter import HttpxAdapter
from .adapters.naabu_adapter import NaabuAdapter
from .adapters.nmap_adapter import NmapAdapter
from .adapters.nuclei_adapter import NucleiAdapter
from .adapters.subfinder_adapter import SubfinderAdapter
from .base import BaseToolAdapter, ToolNotAvailable
from .pipeline import Stage, stages_for

log = logging.getLogger("vulnforge.orchestrator")

# Registry: nome lógico → adapter. Ferramentas do pipeline sem adapter aqui são
# simplesmente puladas (registradas), não quebram o fluxo.
_REGISTRY: dict[str, BaseToolAdapter] = {
    "nmap": NmapAdapter(),
    "nuclei": NucleiAdapter(),
    "naabu": NaabuAdapter(),
    "dnsx": DnsxAdapter(),
    "subfinder": SubfinderAdapter(),
    "httpx": HttpxAdapter(),
}


@dataclass
class ScanReport:
    scan_id: Optional[int]
    perspective: Perspective
    findings: list[Finding] = field(default_factory=list)
    skipped_tools: list[str] = field(default_factory=list)
    stages_run: list[str] = field(default_factory=list)


ProgressCb = Callable[[str], None]


class Orchestrator:
    def __init__(self, store: Optional[FindingStore] = None,
                 registry: Optional[dict[str, BaseToolAdapter]] = None) -> None:
        self._store = store
        self._registry = registry or _REGISTRY

    def _resolve_stage_tools(self, stage: Stage, perspective: Perspective,
                             skipped: list[str], emit: ProgressCb) -> list[BaseToolAdapter]:
        """Filtra as ferramentas de um estágio: precisam existir no registry,
        suportar a perspectiva e estar disponíveis. Decisão via metadados, sem
        ``if`` de perspectiva no meio do fluxo."""
        adapters: list[BaseToolAdapter] = []
        for tool in stage.tools:
            adapter = self._registry.get(tool)
            if adapter is None:
                continue  # ferramenta declarada no pipeline mas ainda sem adapter
            if not adapter.runs_in(perspective):
                continue  # incompatível com a perspectiva (ex.: subfinder em INTERNAL)
            if not adapter.available():
                if tool not in skipped:
                    skipped.append(tool)
                    emit(f"[{tool}] indisponível — pulado")
                continue
            adapters.append(adapter)
        return adapters

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
            adapters = self._resolve_stage_tools(stage, persp, skipped, emit)
            if not adapters:
                continue
            stages_run.append(stage.name)
            emit(f"== estágio '{stage.name}': {[a.name for a in adapters]} ==")
            # ferramentas do mesmo estágio rodam em paralelo (respeitando rate limit).
            jobs = [(adapter, target) for adapter in adapters for target in targets]
            max_workers = len(jobs) if stage.parallel else 1
            with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
                results = pool.map(lambda j: self._safe_scan(*j, emit=emit, **tool_opts), jobs)
                for res in results:
                    raw.extend(res)

        # carimba a perspectiva em cada finding (rastreabilidade da origem).
        for f in raw:
            f.perspective = persp

        findings = deduplicate(raw)  # dedup dentro da perspectiva (fingerprint inclui persp)
        findings.sort(key=lambda f: f.severity.rank, reverse=True)

        if self._store and scan_id is not None:
            self._store.add_findings(scan_id, findings)
            self._store.finish_scan(scan_id)

        emit(f"scan concluído: {len(findings)} findings, {len(stages_run)} estágios, "
             f"{len(skipped)} ferramentas puladas")
        return ScanReport(scan_id=scan_id, perspective=persp, findings=findings,
                          skipped_tools=skipped, stages_run=stages_run)

    def _safe_scan(self, adapter: BaseToolAdapter, target: str, *,
                   emit: ProgressCb, **opts) -> list[Finding]:
        """Executa um adapter isolando falhas: um erro registra e segue (§13)."""
        try:
            return adapter.scan(target, **opts)
        except ToolNotAvailable as exc:
            emit(f"[{adapter.name}] indisponível: {exc}")
        except ScopeViolation:
            raise
        except Exception as exc:  # noqa: BLE001 — um adapter não derruba o pipeline
            emit(f"[{adapter.name}] erro em {target}: {exc}")
        return []
