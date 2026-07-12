"""Primitivas do relatório corporativo — determinísticas, sem I/O nem IA.

Reúne o que eleva o PDF/HTML ao nível de plataforma comercial de VM, sem fabricar
dado (§3.1): classificação da informação, identificador único, score de postura,
mascaramento parcial de segredos e **gráficos SVG inline** (sem dependência nova,
renderizáveis pelo WeasyPrint). Cada número tem uma fórmula auditável.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from enum import Enum

from ..findings.schema import Finding, Severity

# ── Classificação da informação ──────────────────────────────────────────────


class Classification(str, Enum):
    """Nível de sensibilidade do relatório (TLP-like). Dirige o destaque visual
    (capa/cabeçalho/rodapé) e o aviso de confidencialidade."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @classmethod
    def from_str(cls, value: str | "Classification" | None) -> "Classification":
        if isinstance(value, Classification):
            return value
        try:
            return cls((value or "confidential").strip().lower())
        except ValueError:
            return cls.CONFIDENTIAL

    @property
    def label(self) -> str:
        return {
            Classification.PUBLIC: "PÚBLICO",
            Classification.INTERNAL: "USO INTERNO",
            Classification.CONFIDENTIAL: "CONFIDENCIAL",
            Classification.RESTRICTED: "RESTRITO",
        }[self]

    @property
    def color(self) -> str:
        return {
            Classification.PUBLIC: "#2e7d32",
            Classification.INTERNAL: "#0b6fa4",
            Classification.CONFIDENTIAL: "#c0392b",
            Classification.RESTRICTED: "#7b0000",
        }[self]

    @property
    def sensitive(self) -> bool:
        """Confidencial/Restrito exigem destaque em todas as páginas + masking."""
        return self in (Classification.CONFIDENTIAL, Classification.RESTRICTED)


# ── Identificador único do relatório ─────────────────────────────────────────


def report_id(dataset_hash: str, generated_at: datetime | None = None) -> str:
    """ID estável e legível: ``EIGAN-YYYYMMDD-XXXXXX`` (data + prefixo do hash do
    dataset). Determinístico para o mesmo conjunto de findings no mesmo dia."""
    day = (generated_at or datetime.now(timezone.utc)).strftime("%Y%m%d")
    suffix = (dataset_hash or "000000")[:6].upper()
    return f"EIGAN-{day}-{suffix}"


# ── Score geral de postura (heurístico, documentado) ─────────────────────────

# Penalidade por severidade (heurística de postura — NÃO é certificação). A soma
# parte de 100 e desce; KEV (exploração ativa) pesa mais. Documentado no relatório.
_PENALTY = {
    Severity.CRITICAL: 22.0,
    Severity.HIGH: 11.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.0,
}
_KEV_EXTRA = 8.0


def security_score(findings: list[Finding]) -> dict:
    """Score 0-100 (maior = melhor) + nota A–F. Heurística determinística sobre as
    severidades + KEV; transparente e reprodutível (não é um selo de conformidade)."""
    score = 100.0
    for f in findings:
        score -= _PENALTY.get(f.severity, 0.0)
        if f.risk and f.risk.kev:
            score -= _KEV_EXTRA
    score = max(0.0, min(100.0, score))
    grade, label, color = _grade(score)
    return {"score": round(score), "grade": grade, "label": label, "color": color}


def _grade(score: float) -> tuple[str, str, str]:
    for threshold, grade, label, color in (
        (90, "A", "Excelente", "#2e7d32"),
        (80, "B", "Boa", "#558b2f"),
        (70, "C", "Aceitável", "#f39c12"),
        (55, "D", "Frágil", "#e67e22"),
        (35, "E", "Crítica", "#c0392b"),
    ):
        if score >= threshold:
            return grade, label, color
    return "F", "Severa", "#7b0000"


# ── Mascaramento parcial de dados sensíveis ──────────────────────────────────

_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S
)
_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_KV_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd|authorization|bearer)\b(\s*[:=]\s*)"
    r"(['\"]?)([^\s'\"]{3,})\3"
)


def _partial(secret: str, keep: int = 4) -> str:
    """Mostra o suficiente para identificar, não para reproduzir: ``AKIA••••MNOP``."""
    if len(secret) <= keep + 2:
        return "•" * len(secret)
    return secret[:keep] + "•" * min(8, max(3, len(secret) - keep - 2)) + secret[-2:]


def mask_sensitive(text: str) -> str:
    """Mascara **parcialmente** segredos/tokens/credenciais num trecho de evidência.

    Por padrão o relatório oculta chaves privadas, access keys, JWTs e valores de
    ``password/token/secret/api_key`` — o suficiente para triagem sem vazar o
    segredo. A versão completa só sai com ``--show-sensitive`` (fluxo do sistema)."""
    if not text:
        return text
    out = _PRIVATE_KEY.sub("[CHAVE PRIVADA OCULTADA]", text)
    out = _AWS_KEY.sub(lambda m: _partial(m.group(0)), out)
    out = _JWT.sub(lambda m: m.group(0)[:6] + "…[JWT OCULTADO]", out)
    out = _KV_SECRET.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{_partial(m.group(4))}", out
    )
    return out


# ── Gráficos SVG inline (sem dependência; WeasyPrint-friendly) ────────────────

_SEV_COLOR = {
    "critical": "#7b0000",
    "high": "#c0392b",
    "medium": "#f39c12",
    "low": "#f1c40f",
    "info": "#7f8c8d",
}


def severity_donut_svg(summary: dict[str, int], size: int = 150) -> str:
    """Donut da distribuição por severidade. Puro SVG (arcos por dasharray)."""
    total = sum(summary.values())
    r = size / 2 - 14
    cx = cy = size / 2
    circ = 2 * math.pi * r
    if total == 0:
        return (
            f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#e5e9f0" stroke-width="16"/>'
            f'<text x="{cx}" y="{cy + 4}" text-anchor="middle" font-size="12" fill="#8a94a6">'
            f"sem findings</text></svg>"
        )
    segments = []
    offset = 0.0
    for sev in ("critical", "high", "medium", "low", "info"):
        count = summary.get(sev, 0)
        if not count:
            continue
        frac = count / total
        seg = frac * circ
        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
            f'stroke="{_SEV_COLOR[sev]}" stroke-width="16" '
            f'stroke-dasharray="{seg:.2f} {circ - seg:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})"/>'
        )
        offset += seg
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#eef1f6" stroke-width="16"/>'
        + "".join(segments)
        + f'<text x="{cx}" y="{cy - 2}" text-anchor="middle" font-size="26" font-weight="700" '
        f'fill="#1a2433">{total}</text>'
        f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" font-size="10" fill="#8a94a6">'
        f"findings</text></svg>"
    )


def score_gauge_svg(score: dict, size: int = 160) -> str:
    """Medidor semicircular do score de postura (0-100), colorido pela nota."""
    val = float(score["score"])
    color = score["color"]
    r = size / 2 - 16
    cx = size / 2
    cy = size / 2 + 10
    # semicírculo de 180°: ângulo 180° (esq) → 0° (dir); fração do score.
    start = math.pi  # 180°
    end = math.pi - (val / 100.0) * math.pi
    x1, y1 = cx + r * math.cos(start), cy - r * math.sin(start)
    x2, y2 = cx + r * math.cos(end), cy - r * math.sin(end)
    bx, by = cx + r * math.cos(0), cy - r * math.sin(0)
    large = 0  # sempre < 180° para o arco preenchido
    return (
        f'<svg width="{size}" height="{size // 2 + 30}" viewBox="0 0 {size} {size // 2 + 30}">'
        f'<path d="M {x1:.1f} {y1:.1f} A {r} {r} 0 0 1 {bx:.1f} {by:.1f}" '
        f'fill="none" stroke="#eef1f6" stroke-width="14" stroke-linecap="round"/>'
        f'<path d="M {x1:.1f} {y1:.1f} A {r} {r} 0 {large} 1 {x2:.1f} {y2:.1f}" '
        f'fill="none" stroke="{color}" stroke-width="14" stroke-linecap="round"/>'
        f'<text x="{cx}" y="{cy - 6}" text-anchor="middle" font-size="30" font-weight="700" '
        f'fill="{color}">{score["score"]}</text>'
        f'<text x="{cx}" y="{cy + 12}" text-anchor="middle" font-size="11" fill="#8a94a6">'
        f"/100 · nota {score['grade']}</text></svg>"
    )
