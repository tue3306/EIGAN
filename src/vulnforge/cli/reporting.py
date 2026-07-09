"""Geração de relatório para a CLI — compartilhado por ``report`` e wizard.

Suporta os cinco formatos (HTML/PDF/JSON/CSV/SARIF) e os dois modelos
(técnico/executivo). Todos funcionam sem IA; a IA só enriquece se houver chave.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..ai.provider import Enricher, default_provider
from ..findings.store import FindingStore
from ..knowledge.loader import KnowledgeBase
from ..report.deterministic import ReportGenerator

_KB_DIR = Path(__file__).resolve().parents[3] / "knowledge" / "skills"

_MACHINE = {"json", "csv", "sarif"}
TOOL_VERSION = "0.2.0"


def build_generator(*, use_ai: bool, feeds_meta: dict | None = None) -> tuple[ReportGenerator, Enricher]:
    enricher = Enricher(KnowledgeBase(_KB_DIR),
                        provider=default_provider() if use_ai else None)
    gen = ReportGenerator(enricher, tool_version=TOOL_VERSION, feeds_meta=feeds_meta or {})
    return gen, enricher


def write_report(store: FindingStore, scan_id: int, *, fmt: str, style: str,
                 out: str | None, use_ai: bool, feeds_meta: dict | None = None
                 ) -> tuple[Path, bool]:
    """Gera o relatório e devolve (caminho, ia_usada). Levanta ValueError se o
    scan não existir."""
    meta = store.get_scan(scan_id)
    if not meta:
        raise ValueError(f"Scan {scan_id} não encontrado.")
    findings = store.get_findings(scan_id)
    targets = json.loads(meta["targets"])
    engagement = meta["engagement"]

    gen, enricher = build_generator(use_ai=use_ai, feeds_meta=feeds_meta)
    out_path = Path(out or f"report_scan_{scan_id}_{style}.{fmt}")

    if fmt in _MACHINE:
        out_path.write_text(gen.export(findings, fmt, engagement=engagement, targets=targets))
    elif fmt == "html":
        out_path.write_text(gen.render_html(findings, engagement=engagement,
                                            targets=targets, style=style))
    else:  # pdf
        gen.render_pdf(findings, out_path, engagement=engagement,
                       targets=targets, style=style)
    return out_path, enricher.ai_enabled
