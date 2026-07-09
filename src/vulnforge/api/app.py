"""API FastAPI (REST versionado + dashboard) — §G.

Exposição HTTP dos casos de uso e das análises (inventário, ATT&CK, conformidade).
REST versionado desde o início (`/api/v1`). O dashboard web consome esta API;
nenhuma regra de negócio vive no frontend. O widget de IA só é sinalizado quando
há um provedor funcional (degrada honestamente sem chave).
"""

from __future__ import annotations

import os
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .. import __version__
from ..ai.provider import default_provider
from ..analysis.attack import map_attack
from ..analysis.compliance import assess_compliance
from ..analysis.inventory import build_inventory, summarize
from ..findings.schema import Finding, Severity
from ..findings.store import FindingStore

app = FastAPI(
    title="VulnForge API",
    version=__version__,
    description="Plataforma modular de operações de segurança (uso autorizado).",
)

_AI_ENV = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "OLLAMA_HOST")
_TOOL_VERSION = __version__


def _db_path() -> str:
    return os.getenv("VULNFORGE_DB", "vulnforge.db")


def _store() -> FindingStore:
    return FindingStore(_db_path())


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


# ── dashboard ───────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    index = Path(__file__).parent / "static" / "index.html"
    if index.exists():
        return index.read_text()
    return (
        "<h1>VulnForge</h1><p>API ativa. Veja <a href='/docs'>/docs</a> e "
        "<code>/api/v1/scans</code>.</p>"
    )
