"""API FastAPI (REST versionado + dashboard) — §G.

Exposição HTTP dos casos de uso e das análises (inventário, ATT&CK, conformidade).
REST versionado desde o início (`/api/v1`). O dashboard web consome esta API;
nenhuma regra de negócio vive no frontend. O widget de IA só é sinalizado quando
há um provedor funcional (degrada honestamente sem chave).
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..ai.provider import AIProviderRequired, default_provider
from ..analysis.attack import map_attack
from ..analysis.compliance import assess_compliance
from ..analysis.inventory import build_inventory, summarize
from ..findings.schema import Finding, Severity
from ..findings.store import FindingStore
from .scan_manager import ScanManager

app = FastAPI(
    title="EIGAN API",
    version=__version__,
    description="Plataforma modular de operações de segurança (uso autorizado).",
)

_AI_ENV = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "OLLAMA_HOST")
_TOOL_VERSION = __version__


def _db_path() -> str:
    return os.getenv("EIGAN_DB", "eigan.db")


def _store() -> FindingStore:
    return FindingStore(_db_path())


# Gerente de scans em background (um por processo). Alimenta a UI em tempo real.
_manager: ScanManager | None = None


def manager() -> ScanManager:
    global _manager
    if _manager is None:
        _manager = ScanManager(_db_path())
    return _manager


def _findings_or_404(store: FindingStore, scan_id: int) -> list[Finding]:
    if not store.get_scan(scan_id):
        raise HTTPException(404, "scan não encontrado")
    return store.get_findings(scan_id)


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


# ── meta / saúde ────────────────────────────────────────────────────────────
class HealthOut(BaseModel):
    status: str
    version: str


@app.get("/api/v1/health", response_model=HealthOut)
def health() -> HealthOut:
    return HealthOut(status="ok", version=_TOOL_VERSION)


@app.get("/api/v1/meta")
def meta() -> dict:
    """Sinaliza estado da IA (para o widget) e versão. ``ai_enabled`` = provedor
    FUNCIONAL; ``ai_key_detected`` = chave no ambiente (mesmo sem provedor pronto)."""
    return {
        "tool_version": _TOOL_VERSION,
        "ai_enabled": default_provider() is not None,
        "ai_key_detected": any(os.getenv(k) for k in _AI_ENV),
    }


@app.get("/api/v1/setup")
def setup_status() -> dict:
    """Estado do ambiente para o onboarding visual: o que falta e como resolver.
    A IA é **obrigatória** (AI-native); PDF/ferramentas degradam graciosamente."""
    from ..cli import doctor as doctor_mod

    report = doctor_mod.gather()
    missing = [t.name for t in report.tools if not t.roadmap and not t.available]
    return {
        "ai": {
            "enabled": default_provider() is not None,
            "required": True,  # AI-native (ADR-0012): sem provedor, o scan é recusado
            "key_detected": any(os.getenv(k) for k in _AI_ENV),
            "hint": "Configure um provedor: EIGAN_AI_PROVIDER + chave (ou Ollama local, offline). "
            "Sem provedor o scan é recusado. Ver docs/ai-providers.md.",
        },
        "pdf": {
            "available": report.pdf_available,
            "detail": report.pdf_detail,
        },
        "tools": {
            "available": report.tools_available,
            "total": len(report.tools),
            "missing_real": missing,
            "hint": "python3 eigan.py --with-tools  (ou eigan doctor --install)",
        },
    }


# ── scans ───────────────────────────────────────────────────────────────────
@app.get("/api/v1/scans")
def list_scans() -> list[dict]:
    return _store().list_scans()


@app.get("/api/v1/stats")
def stats() -> dict:
    """Números agregados para a visão geral do dashboard."""
    store = _store()
    scans = store.list_scans()
    latest = scans[0]["id"] if scans else None
    findings = store.get_findings(latest) if latest else []
    return {
        "scans": len(scans),
        "latest_scan": latest,
        "findings": len(findings),
        "severity": _severity_counts(findings),
        "kev": sum(1 for f in findings if f.risk and f.risk.kev),
    }


@app.get("/api/v1/scans/{scan_id}")
def scan_detail(scan_id: int) -> dict:
    store = _store()
    meta_ = store.get_scan(scan_id)
    if not meta_:
        raise HTTPException(404, "scan não encontrado")
    findings = store.get_findings(scan_id)
    return {"scan": meta_, "count": len(findings), "severity": _severity_counts(findings)}


@app.get("/api/v1/scans/{scan_id}/findings")
def scan_findings(scan_id: int, severity: str | None = Query(default=None)) -> dict:
    store = _store()
    findings = _findings_or_404(store, scan_id)
    if severity:
        findings = [f for f in findings if f.severity.value == severity.lower()]
    return {
        "count": len(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }


@app.get("/api/v1/scans/{scan_id}/inventory")
def scan_inventory(scan_id: int) -> dict:
    findings = _findings_or_404(_store(), scan_id)
    inv = build_inventory(findings)
    return {"summary": summarize(inv), "assets": [asdict(a) for a in inv]}


@app.get("/api/v1/scans/{scan_id}/attack")
def scan_attack(scan_id: int) -> dict:
    findings = _findings_or_404(_store(), scan_id)
    return asdict(map_attack(findings))


@app.get("/api/v1/scans/{scan_id}/compliance")
def scan_compliance(scan_id: int) -> dict:
    findings = _findings_or_404(_store(), scan_id)
    return asdict(assess_compliance(findings))


_REPORT_MEDIA = {
    "pdf": "application/pdf",
    "html": "text/html",
    "json": "application/json",
    "csv": "text/csv",
    "sarif": "application/json",
}


@app.get("/api/v1/scans/{scan_id}/report")
def scan_report(
    scan_id: int,
    fmt: str = Query("html", alias="format"),
    style: str = Query("executive"),
    ai: bool = Query(False),
) -> FileResponse:
    """Gera e devolve o relatório para download. PDF degrada para HTML (§13)."""
    from ..cli.reporting import write_report
    from ..cli.session import feeds_meta
    from ..engine.feeds import FeedCache

    store = _store()
    if not store.get_scan(scan_id):
        raise HTTPException(404, "scan não encontrado")
    fmt = fmt.lower()
    if fmt not in _REPORT_MEDIA:
        raise HTTPException(400, f"formato inválido: {fmt}")
    if style not in ("technical", "executive"):
        style = "executive"

    import tempfile

    fmeta = feeds_meta(FeedCache.load())
    tmp = Path(tempfile.gettempdir())
    headers: dict[str, str] = {}
    try:
        path, _ = write_report(
            store,
            scan_id,
            fmt=fmt,
            style=style,
            out=str(tmp / f"eigan_scan{scan_id}_{style}.{fmt}"),
            use_ai=ai,
            feeds_meta=fmeta,
        )
    except RuntimeError as exc:  # PDF indisponível → HTML equivalente (§13)
        if fmt != "pdf":
            raise HTTPException(500, f"falha ao gerar relatório: {exc}") from exc
        fmt = "html"
        headers["X-Report-Degraded"] = "pdf->html"
        path, _ = write_report(
            store,
            scan_id,
            fmt="html",
            style=style,
            out=str(tmp / f"eigan_scan{scan_id}_{style}.html"),
            use_ai=ai,
            feeds_meta=fmeta,
        )
    return FileResponse(
        str(path), media_type=_REPORT_MEDIA[fmt], filename=path.name, headers=headers
    )


# ── findings / assets globais (visão da UI, sobre o último scan) ─────────────
def _latest_scan_id(store: FindingStore) -> int | None:
    scans = store.list_scans()
    return scans[0]["id"] if scans else None


@app.get("/api/v1/findings")
def findings_global(
    severity: str | None = Query(default=None),
    scan_id: int | None = Query(default=None),
) -> dict:
    """Findings filtrados. Sem ``scan_id``, usa o último scan (visão do dashboard)."""
    store = _store()
    sid = scan_id if scan_id is not None else _latest_scan_id(store)
    findings = store.get_findings(sid) if sid is not None else []
    if severity:
        findings = [f for f in findings if f.severity.value == severity.lower()]
    return {
        "scan_id": sid,
        "count": len(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }


@app.get("/api/v1/assets")
def assets_global(scan_id: int | None = Query(default=None)) -> dict:
    """Inventário de ativos do último scan (ou de ``scan_id``), ordenado por risco."""
    store = _store()
    sid = scan_id if scan_id is not None else _latest_scan_id(store)
    findings = store.get_findings(sid) if sid is not None else []
    inv = build_inventory(findings)
    inv.sort(key=lambda a: a.max_risk, reverse=True)
    return {"scan_id": sid, "summary": summarize(inv), "assets": [asdict(a) for a in inv]}


# ── scans em tempo real (jobs) ───────────────────────────────────────────────
class ScanRequest(BaseModel):
    """Corpo do POST /scans vindo do wizard. ``authorized`` é o consent gate."""

    targets: list[str] = Field(min_length=1)
    perspective: str = "external"
    objective: str = "standard"  # quick | standard | deep | ai
    use_ai: bool = False
    authorized: bool = False
    override_perspective: bool = False


@app.post("/api/v1/scans", status_code=202)
def start_scan(req: ScanRequest) -> dict:
    """Inicia um scan em background. Retorna o ``job_id`` para acompanhar o progresso.

    Recusa (403) sem afirmação de autorização — o consent gate é preservado."""
    try:
        job = manager().start(
            targets=req.targets,
            perspective=req.perspective,
            objective=req.objective,
            authorized=req.authorized,
            use_ai=req.use_ai,
            override_perspective=req.override_perspective,
        )
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except AIProviderRequired as exc:
        # 428 Precondition Required: falta um provedor de IA (§3.4/ADR-0012).
        raise HTTPException(428, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return job.summary()


@app.get("/api/v1/jobs")
def list_jobs() -> list[dict]:
    return manager().list_jobs()


def _job_or_404(job_id: str):
    job = manager().get(job_id)
    if job is None:
        raise HTTPException(404, "job não encontrado")
    return job


@app.get("/api/v1/jobs/{job_id}")
def job_status(job_id: str) -> dict:
    return _job_or_404(job_id).summary()


@app.get("/api/v1/jobs/{job_id}/progress")
def job_progress(job_id: str, since: int = Query(default=0, ge=0)) -> dict:
    """Polling de progresso: eventos a partir de ``since`` + novo cursor (fallback ao WS)."""
    job = _job_or_404(job_id)
    evs, cursor = job.events_since(since)
    return {"status": job.status, "cursor": cursor, "events": evs}


@app.get("/api/v1/jobs/{job_id}/cascade-log")
def job_cascade_log(job_id: str) -> dict:
    """Log justificado de cada disparo de cascata (qual ferramenta e por quê)."""
    job = _job_or_404(job_id)
    return {"count": len(job.cascade_log), "cascade_log": job.cascade_log}


@app.post("/api/v1/jobs/{job_id}/cancel")
def job_cancel(job_id: str) -> dict:
    _job_or_404(job_id)
    ok = manager().cancel(job_id)
    return {"cancelled": ok}


@app.websocket("/ws/scans/{job_id}/progress")
async def scan_progress_ws(websocket: WebSocket, job_id: str) -> None:
    """Stream de progresso em tempo real: fases, descobertas, cascatas, execução.

    Faz replay do histórico ao conectar e depois entrega eventos novos conforme
    chegam ao buffer do job (ponte thread→async por polling curto do buffer)."""
    await websocket.accept()
    job = manager().get(job_id)
    if job is None:
        await websocket.send_json({"type": "error", "message": "job não encontrado"})
        await websocket.close()
        return
    cursor = 0
    try:
        while True:
            evs, cursor = job.events_since(cursor)
            for event in evs:
                await websocket.send_json(event)
            if job.finished:
                evs, cursor = job.events_since(cursor)
                for event in evs:
                    await websocket.send_json(event)
                await websocket.send_json({"type": "stream_end", "status": job.status})
                break
            await asyncio.sleep(0.25)
    except WebSocketDisconnect:
        return


# ── dashboard (SPA estática) ─────────────────────────────────────────────────
_STATIC_DIR = Path(__file__).parent / "static"


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    index = _STATIC_DIR / "index.html"
    if index.exists():
        return index.read_text()
    return (
        "<h1>EIGAN</h1><p>API ativa. Veja <a href='/docs'>/docs</a> e "
        "<code>/api/v1/scans</code>.</p>"
    )


# assets estáticos (css/js/componentes). Montado por último para não capturar /api.
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
