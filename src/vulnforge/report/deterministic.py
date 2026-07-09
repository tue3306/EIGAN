"""Gerador de relatório (HTML → PDF).

Modo determinístico por padrão (CLAUDE.md §11): monta o relatório a partir dos
findings + base de conhecimento, sem nenhuma chave de API. O sumário executivo
por IA é opcional e cai automaticamente para o texto determinístico se ausente.

Saída HTML sempre funciona; PDF requer WeasyPrint (opcional).
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..ai.provider import Enricher
from ..findings.schema import Finding, Severity

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _dataset_hash(findings: list[Finding]) -> str:
    blob = json.dumps([f.model_dump(mode="json") for f in findings], sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


class ReportGenerator:
    def __init__(self, enricher: Enricher, *, brand: str = "VulnForge",
                 tool_version: str = "0.1.0") -> None:
        self._enricher = enricher
        self._brand = brand
        self._tool_version = tool_version
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def _context(self, findings: list[Finding], engagement: str, targets: list[str],
                 executive_summary: str, executive_ai: bool) -> dict:
        counts = Counter(f.severity for f in findings)
        summary = {s.value: counts.get(s, 0) for s in _SEV_ORDER}
        enrichment = [self._enricher.explain(f) for f in findings]
        return {
            "brand": self._brand,
            "engagement": engagement,
            "targets": targets,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "tool_version": self._tool_version,
            "dataset_hash": _dataset_hash(findings),
            "summary": summary,
            "findings": findings,
            "enrichment": enrichment,
            "executive_summary": executive_summary,
            "executive_ai": executive_ai,
        }

    def render_html(self, findings: list[Finding], *, engagement: str,
                    targets: list[str], executive_summary: str = "") -> str:
        ctx = self._context(
            findings, engagement, targets, executive_summary,
            executive_ai=bool(executive_summary) and self._enricher.ai_enabled,
        )
        return self._env.get_template("report.html.j2").render(**ctx)

    def render_pdf(self, findings: list[Finding], out_path: str | Path, *,
                   engagement: str, targets: list[str], executive_summary: str = "") -> Path:
        html = self.render_html(
            findings, engagement=engagement, targets=targets,
            executive_summary=executive_summary,
        )
        out = Path(out_path)
        try:
            from weasyprint import HTML  # import tardio: PDF é opcional
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "WeasyPrint não instalado. Use render_html() ou instale weasyprint."
            ) from exc
        HTML(string=html).write_pdf(str(out))
        return out
