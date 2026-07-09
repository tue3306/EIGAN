"""Gerador de relatórios — Técnico e Executivo, em HTML/PDF + exporters.

Modo determinístico por padrão (§11): monta o relatório a partir dos findings +
correlação + base de conhecimento, **sem nenhuma chave de API**. O sumário
executivo e as narrativas por IA são opcionais e caem automaticamente para o
texto determinístico se ausentes.

Saídas: HTML sempre; PDF requer WeasyPrint (opcional); JSON/CSV/SARIF via
:mod:`vulnforge.report.exporters` (todos sem IA).
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..ai.provider import Enricher
from ..engine.correlation import AssetCorrelation, correlate_assets
from ..findings.schema import Finding, Severity
from . import exporters

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _dataset_hash(findings: list[Finding]) -> str:
    blob = json.dumps([f.model_dump(mode="json") for f in findings], sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


class ReportGenerator:
    def __init__(self, enricher: Enricher, *, brand: str = "VulnForge",
                 tool_version: str = "0.2.0", feeds_meta: dict | None = None) -> None:
        self._enricher = enricher
        self._brand = brand
        self._tool_version = tool_version
        self._feeds_meta = feeds_meta or {}
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    # ── metadados comuns ────────────────────────────────────────────────────────
    def _base_meta(self, findings: list[Finding], engagement: str,
                   targets: list[str]) -> dict:
        return {
            "brand": self._brand,
            "engagement": engagement,
            "targets": targets,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "tool_version": self._tool_version,
            "dataset_hash": _dataset_hash(findings),
            "feeds": {"kev": self._feeds_meta.get("kev", ""),
                      "epss": self._feeds_meta.get("epss", "")},
        }

    def _summary(self, findings: list[Finding]) -> dict[str, int]:
        counts = Counter(f.severity for f in findings)
        return {s.value: counts.get(s, 0) for s in _SEV_ORDER}

    # ── relatório técnico (detalhado) ───────────────────────────────────────────
    def render_html(self, findings: list[Finding], *, engagement: str,
                    targets: list[str], executive_summary: str = "",
                    style: str = "technical") -> str:
        if style == "executive":
            return self.render_executive_html(
                findings, engagement=engagement, targets=targets,
                executive_summary=executive_summary)
        ctx = self._base_meta(findings, engagement, targets)
        ctx.update({
            "summary": self._summary(findings),
            "findings": findings,
            "enrichment": [self._enricher.explain(f) for f in findings],
            "executive_summary": executive_summary,
            "executive_ai": bool(executive_summary) and self._enricher.ai_enabled,
        })
        return self._env.get_template("report.html.j2").render(**ctx)

    # ── relatório executivo (risco/negócio) ─────────────────────────────────────
    def render_executive_html(self, findings: list[Finding], *, engagement: str,
                              targets: list[str], executive_summary: str = "") -> str:
        correlations = correlate_assets(findings)
        summary = self._summary(findings)
        kev_count = sum(1 for f in findings if f.risk and f.risk.kev)
        top_risks = sorted(findings, key=lambda f: f.risk_rank, reverse=True)[:15]

        ai = bool(executive_summary) and self._enricher.ai_enabled
        if not executive_summary:
            executive_summary = self._deterministic_executive(
                findings, correlations, summary, kev_count)

        ctx = self._base_meta(findings, engagement, targets)
        ctx.update({
            "summary": summary,
            "correlations": correlations,
            "kev_count": kev_count,
            "top_risks": top_risks,
            "recommendations": self._recommendations(findings),
            "executive_summary": executive_summary,
            "executive_ai": ai,
        })
        return self._env.get_template("executive.html.j2").render(**ctx)

    def _deterministic_executive(self, findings: list[Finding],
                                 correlations: list[AssetCorrelation],
                                 summary: dict[str, int], kev_count: int) -> str:
        na = len(correlations)
        crit, high = summary.get("critical", 0), summary.get("high", 0)
        parts = [f"A avaliação cobriu {na} ativo(s) e identificou {len(findings)} achado(s)."]
        if crit or high:
            parts.append(f"Destes, {crit} de severidade crítica e {high} alta requerem "
                         "atenção prioritária.")
        else:
            parts.append("Nenhum achado de severidade alta ou crítica foi identificado.")
        if kev_count:
            parts.append(f"{kev_count} correspondem a vulnerabilidades com exploração ativa "
                         "conhecida (CISA KEV), exigindo correção imediata.")
        xp = sum(1 for a in correlations if a.cross_perspective)
        if xp:
            parts.append(f"{xp} ativo(s) apresentam exposição externa e interna, ampliando a "
                         "superfície de ataque.")
        return " ".join(parts)

    def _recommendations(self, findings: list[Finding]) -> list[str]:
        recs: list[str] = []
        kev = sorted({f.title for f in findings if f.risk and f.risk.kev})
        if kev:
            recs.append("Priorizar a correção imediata dos itens em CISA KEV (exploração ativa): "
                        + "; ".join(kev[:5]) + (" …" if len(kev) > 5 else "") + ".")
        for f in sorted(findings, key=lambda f: f.risk_rank, reverse=True)[:5]:
            rem = self._enricher.explain(f).remediation.strip()
            if rem:
                first = rem.splitlines()[0][:200]
                line = f"{f.title}: {first}"
                if line not in recs:
                    recs.append(line)
        if not recs:
            recs.append("Manter processo contínuo de gestão de vulnerabilidades e aplicar "
                        "hardening (CIS Benchmarks / NIST SP 800-53).")
        return recs

    # ── PDF (opcional) ──────────────────────────────────────────────────────────
    def render_pdf(self, findings: list[Finding], out_path: str | Path, *,
                   engagement: str, targets: list[str], executive_summary: str = "",
                   style: str = "technical") -> Path:
        html = self.render_html(findings, engagement=engagement, targets=targets,
                                executive_summary=executive_summary, style=style)
        out = Path(out_path)
        try:
            from weasyprint import HTML  # import tardio: PDF é opcional
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "WeasyPrint não instalado. Use render_html() ou instale 'vulnforge[pdf]'."
            ) from exc
        HTML(string=html).write_pdf(str(out))
        return out

    # ── exporters de máquina (JSON/CSV/SARIF — sem IA) ──────────────────────────
    def export(self, findings: list[Finding], fmt: str, *, engagement: str,
               targets: list[str]) -> str:
        meta = self._base_meta(findings, engagement, targets)
        if fmt == "json":
            return exporters.to_json(findings, meta=meta)
        if fmt == "csv":
            return exporters.to_csv(findings)
        if fmt == "sarif":
            return exporters.to_sarif(findings, tool_version=self._tool_version, meta=meta)
        raise ValueError(f"Formato de export desconhecido: {fmt!r}. Use json|csv|sarif.")
