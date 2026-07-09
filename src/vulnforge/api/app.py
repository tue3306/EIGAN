"""API FastAPI (REST versionado + WebSocket de progresso).

Exposição HTTP dos casos de uso. REST versionado desde o início (`/api/v1`,
CLAUDE.md §9). O dashboard web consome esta API; nenhuma regra de negócio vive
no frontend.

Escopo desta fase: endpoints de leitura (scans/findings) + saúde + WS de
progresso. Criação de scan via API reusa o Orchestrator com o mesmo guardrail
de escopo do CLI.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from ..findings.store import FindingStore

app = FastAPI(
    title="VulnForge API",
    version="0.2.0",
    description="Plataforma modular de operações de segurança (uso autorizado).",
)


def _db_path() -> str:
    return os.getenv("VULNFORGE_DB", "vulnforge.db")


def _store() -> FindingStore:
    return FindingStore(_db_path())


class HealthOut(BaseModel):
    status: str
    version: str


@app.get("/api/v1/health", response_model=HealthOut)
def health() -> HealthOut:
    return HealthOut(status="ok", version="0.1.0")


@app.get("/api/v1/scans")
def list_scans() -> list[dict]:
    return _store().list_scans()


@app.get("/api/v1/scans/{scan_id}/findings")
def scan_findings(scan_id: int) -> dict:
    store = _store()
    meta = store.get_scan(scan_id)
    if not meta:
        raise HTTPException(404, "scan não encontrado")
    findings = [f.model_dump(mode="json") for f in store.get_findings(scan_id)]
    return {"scan": meta, "findings": findings, "count": len(findings)}


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    """Dashboard mínimo server-rendered (placeholder da Fase 3).

    Justificativa da escolha server-rendered: entrega um dashboard funcional sem
    build de frontend, mantendo a API como fonte única de dados. A UI React+Vite
    completa é evolução da Fase 3, consumindo os mesmos endpoints /api/v1.
    """
    index = Path(__file__).parent / "static" / "index.html"
    if index.exists():
        return index.read_text()
    return (
        "<h1>VulnForge</h1><p>API ativa. Veja <a href='/docs'>/docs</a> e "
        "<code>/api/v1/scans</code>.</p>"
    )
