"""Context Manager — monta o contexto de um scan para a IA (grounding).

A IA só pode falar sobre o que foi coletado (§3.1 anti-invenção). Este módulo
condensa os findings + metadados de um scan num resumo compacto e factual que vai
como contexto na conversa/análise. Nada aqui inventa: só serializa o que existe.

Puro (domínio) — recebe os findings já normalizados e devolve texto; a redaction
de segredos/PII é aplicada pela camada de provedor antes de sair para a nuvem.
"""

from __future__ import annotations

from collections import Counter

from ..findings.schema import Finding, Severity

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    c = Counter(f.severity.value for f in findings)
    return {s.value: c.get(s.value, 0) for s in _SEV_ORDER}


def _risk(f: Finding) -> float:
    return (
        f.risk.score
        if f.risk
        else float({"critical": 80, "high": 60, "medium": 40}.get(f.severity.value, 10))
    )


def build_scan_context(
    findings: list[Finding],
    *,
    engagement: str = "",
    targets: list[str] | None = None,
    profile: str = "",
    max_findings: int = 40,
) -> str:
    """Resumo factual do scan para grounding da IA. Ordena por risco e corta o
    excesso para caber no contexto — mantendo os mais críticos."""
    if not findings:
        return (
            f"Scan de {', '.join(targets or [])} ({engagement or 'ad-hoc'}) ainda sem "
            "findings coletados."
        )
    counts = severity_counts(findings)
    tools = sorted({f.source_tool for f in findings})
    assets = sorted({f.affected_asset for f in findings})[:20]
    ranked = sorted(findings, key=lambda f: (_risk(f), f.severity.rank), reverse=True)

    lines: list[str] = [
        f"ALVO(S): {', '.join(targets or []) or '—'}",
        f"ENGAJAMENTO: {engagement or 'ad-hoc'}  ·  PERFIL: {profile or '—'}",
        f"TOTAL DE FINDINGS: {len(findings)}  ·  "
        + " · ".join(f"{k}={v}" for k, v in counts.items() if v),
        f"FERRAMENTAS USADAS: {', '.join(tools)}",
        f"ATIVOS ({len(assets)}): {', '.join(assets)}",
        "",
        f"FINDINGS (top {min(max_findings, len(ranked))} por risco):",
    ]
    for i, f in enumerate(ranked[:max_findings], start=1):
        risk = f"{_risk(f):.0f}"
        extra = " · ".join(
            x
            for x in (
                f"CWE {f.cwe}" if f.cwe else "",
                f"OWASP {f.owasp}" if f.owasp else "",
                f"ATT&CK {f.attack_technique}" if f.attack_technique else "",
                "KEV" if (f.risk and f.risk.kev) else "",
            )
            if x
        )
        lines.append(
            f"  {i}. [{f.severity.value.upper()}] (risco {risk}) {f.title} "
            f"@ {f.affected_asset} — via {f.source_tool}" + (f"  [{extra}]" if extra else "")
        )
    if len(ranked) > max_findings:
        lines.append(f"  … (+{len(ranked) - max_findings} findings de menor risco omitidos)")
    return "\n".join(lines)
