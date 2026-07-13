"""Gerência de scans em background para a interface web (§5 do prompt de interface).

Um scan disparado pela UI roda em uma thread daemon enquanto a API continua
respondendo. Cada job mantém um **buffer de eventos** (fases, descobertas,
cascatas, execução de ferramenta) que a UI consome via WebSocket/polling em tempo
real. A camada de segurança é **preservada, não removida** (§2): o corpo do POST
precisa afirmar autorização — sem isso, o scan é recusado (equivalente ao consent
gate inline da CLI).

Este módulo é a fronteira entre o mundo síncrono/threaded do engine e o mundo
async da API: o :class:`~eigan.engine.cognitive.CognitiveEngine` emite eventos por um
:class:`~eigan.engine.events.EventSink` síncrono; o buffer é lido pelo
handler async. A ponte é um buffer protegido por lock (simples e robusto) — sem
malabarismo de event loop entre threads.
"""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from typing import Any, Optional

from ..engine import events as ev
from ..engine.cognitive import CognitiveEngine, Goal, GoalKind
from ..engine.feeds import FeedCache
from ..engine.risk import RiskScorer
from ..findings.store import FindingStore
from ..engine.registry import PluginRegistry
from ..perspective import Perspective, validate_target
from ..security.onboarding import build_scope
from ..security.scope import ScopeViolation

# perfis expostos pela UI → perfil interno do pipeline (engine/pipeline.py).
OBJECTIVE_PROFILE = {
    "quick": "quick",
    "standard": "standard",
    "deep": "deep",
    "ai": "standard",  # "deixe a IA decidir": IA orquestra sobre o pipeline padrão
}

# objetivo do EIGAN por perspectiva (foco v1.0: Web + Infra, Outside-In/Inside-Out).
# UNIFIED (default do produto) → avaliação completa: recon externo + rede num só scan.
_GOAL_BY_PERSPECTIVE = {
    Perspective.UNIFIED: GoalKind.FULL_ASSESSMENT,
    Perspective.EXTERNAL: GoalKind.ATTACK_SURFACE,
    Perspective.INTERNAL: GoalKind.NETWORK_ASSESSMENT,
}


def _ai_completion(use_ai: bool):
    """Provedor de IA (se pedido e disponível) para o AgenticPlanner; senão None
    → o engine cai no DeterministicPlanner (fallback §3.4)."""
    if not use_ai:
        return None
    try:
        from ..ai.provider import default_provider

        return default_provider()
    except Exception:  # noqa: BLE001 — IA indisponível nunca quebra o scan
        return None


class ScanCancelled(Exception):
    """Sinaliza cancelamento cooperativo — levantado no próximo evento emitido."""


@dataclass
class ScanJob:
    """Estado observável de um scan em andamento ou concluído."""

    id: str
    targets: list[str]
    perspective: str
    profile: str
    use_ai: bool = False
    status: str = "queued"  # queued | running | completed | failed | cancelled
    scan_id: Optional[int] = None  # id persistido (FindingStore) quando disponível
    error: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)
    cascade_log: list[dict[str, Any]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)

    # ── buffer de eventos (thread-safe) ─────────────────────────────────────
    def append(self, event: dict[str, Any]) -> None:
        with self._lock:
            self.events.append(event)
            if event.get("type") == "cascade_log":
                self.cascade_log.append(event)
            if event.get("type") == "scan_status" and event.get("scan_id") is not None:
                self.scan_id = event["scan_id"]

    def events_since(self, index: int) -> tuple[list[dict[str, Any]], int]:
        """Eventos a partir de ``index`` e o novo cursor (para polling/WS)."""
        with self._lock:
            slice_ = self.events[index:]
            return list(slice_), len(self.events)

    def summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "id": self.id,
                "targets": self.targets,
                "perspective": self.perspective,
                "profile": self.profile,
                "use_ai": self.use_ai,
                "status": self.status,
                "scan_id": self.scan_id,
                "error": self.error,
                "events": len(self.events),
                "cascade_tools": len({c["tool"] for c in self.cascade_log}),
            }

    @property
    def finished(self) -> bool:
        return self.status in ("completed", "failed", "cancelled")

    def request_cancel(self) -> None:
        self._cancel.set()

    def _check_cancel(self) -> None:
        if self._cancel.is_set():
            raise ScanCancelled()


class _JobSink:
    """EventSink que grava no buffer do job e respeita cancelamento cooperativo."""

    def __init__(self, job: ScanJob) -> None:
        self._job = job

    def emit(self, event: dict[str, Any]) -> None:
        self._job.append(event)
        self._job._check_cancel()  # aborta no próximo ponto de emissão se pedido


class ScanManager:
    """Registro em memória dos jobs de scan. Um por processo de API."""

    def __init__(
        self, db_path: str = "eigan.db", registry: Optional[PluginRegistry] = None
    ) -> None:
        self._db_path = db_path
        # Registry injetável (DI) — o default descobre os plugins do repo/wheel.
        # Testes passam um registry controlado para rodar hermeticamente.
        self._registry = registry
        self._jobs: dict[str, ScanJob] = {}
        self._counter = itertools.count(1)
        self._lock = threading.Lock()

    def get(self, job_id: str) -> Optional[ScanJob]:
        return self._jobs.get(job_id)

    def list_jobs(self) -> list[dict[str, Any]]:
        return [j.summary() for j in self._jobs.values()]

    def start(
        self,
        *,
        targets: list[str],
        perspective: str,
        objective: str,
        authorized: bool,
        use_ai: bool = False,
        override_perspective: bool = False,
    ) -> ScanJob:
        """Cria e inicia um job. ``authorized`` é o consent gate — obrigatório."""
        if not authorized:
            # Consent gate preservado (CLAUDE.md §2): nunca removido, só simplificado.
            raise PermissionError(
                "Autorização ausente: confirme que você tem permissão para escanear os alvos."
            )
        # Gate AI-native (§3.4/ADR-0012): EIGAN é um agente de IA — sem provedor,
        # não há scan. Levanta AIProviderRequired (mapeado p/ HTTP 428 no endpoint).
        from ..ai.provider import require_provider

        require_provider()
        if not targets:
            raise ValueError("Informe ao menos um alvo.")
        for t in targets:  # forma do alvo (§5): rejeita cedo (400) — anti argument-injection
            validate_target(t)
        try:
            persp = Perspective(perspective.strip().lower())
        except ValueError as exc:
            raise ValueError(f"Perspectiva inválida: {perspective!r}") from exc
        profile = OBJECTIVE_PROFILE.get(objective.strip().lower(), "standard")

        with self._lock:
            job_id = f"job-{next(self._counter)}"
        job = ScanJob(
            id=job_id,
            targets=list(targets),
            perspective=persp.value,
            profile=profile,
            use_ai=use_ai,
        )
        self._jobs[job_id] = job

        thread = threading.Thread(
            target=self._run,
            args=(job, persp, profile, override_perspective),
            name=f"scan-{job_id}",
            daemon=True,
        )
        thread.start()
        return job

    def cancel(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if not job or job.finished:
            return False
        job.request_cancel()
        return True

    # ── execução ────────────────────────────────────────────────────────────
    def _run(self, job: ScanJob, perspective: Perspective, profile: str, override: bool) -> None:
        job.status = "running"
        sink = _JobSink(job)
        try:
            scope = build_scope(None, job.targets, perspective)
            feeds = FeedCache.load()
            risk = RiskScorer(feeds, online=False)  # enriquecimento online é opt-in
            store = FindingStore(self._db_path)
            # EIGAN: a IA comanda o scan (AgenticPlanner) quando disponível; senão
            # o loop determinístico. A cascata declarativa é o piso de segurança.
            completion = _ai_completion(job.use_ai)
            engine = CognitiveEngine(self._registry, risk=risk, store=store, completion=completion)
            goal = Goal.build(
                _GOAL_BY_PERSPECTIVE.get(perspective, GoalKind.ATTACK_SURFACE),
                job.targets,
                perspective=perspective,
                profile=profile,
            )
            for t in job.targets:  # falha rápida se um alvo é totalmente não autorizado
                scope.enforce(t, perspective=perspective, override=override)
            # Intensidade → opções de ferramenta (rate/timing/stealth/portas): a
            # mesma capacidade roda com as melhores opções para o objetivo.
            from ..engine.tuning import tool_options

            opts = tool_options(profile, perspective)
            engine.run(goal, scope=scope, override_perspective=override, sink=sink, **opts)
            store.close()
            job.status = "completed"
        except ScanCancelled:
            job.status = "cancelled"
            job.append(ev.scan_status(job.scan_id, "cancelled", "cancelado pelo usuário"))
        except ScopeViolation as exc:
            job.status = "failed"
            job.error = str(exc)
            job.append(ev.scan_status(job.scan_id, "failed", f"bloqueado: {exc}"))
        except Exception as exc:  # noqa: BLE001 — erro de scan não derruba a API
            job.status = "failed"
            job.error = str(exc)
            job.append(ev.scan_status(job.scan_id, "failed", str(exc)))
