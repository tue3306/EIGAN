"""Blue Engine — executa capacidades defensivas e persiste (ADR-0008, Pilar Blue).

Diferente do loop cognitivo (host-scoped, Red recon), a análise defensiva opera
sobre **artefatos** (arquivos/diretórios de log), não hosts — então tem seu
caminho de execução próprio. Mas reusa TODO o downstream: o schema `Finding`, a
dedup, o Risk Engine, o `FindingStore`, a análise + o plano de remediação por IA
e a correlação Purple. Assim as detecções aparecem no dashboard e nos relatórios
exatamente como os findings Red.

AI-native (§3.4): a IA analisa e prioriza as detecções (o detector é
determinístico; a inteligência é da IA). O chamador deve exigir um provedor.
Grounding (§3.3): só roda plugins reais do registry (ids inventados não existem).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..findings.dedup import deduplicate
from ..findings.schema import Finding
from ..findings.store import FindingStore
from ..perspective import Perspective
from .registry import PluginRegistry
from .risk import RiskScorer

log = logging.getLogger("eigan.blue")

_LOG_ANALYSIS = "log-analysis"


@dataclass
class BlueReport:
    """Resultado de uma execução defensiva (compat parcial com CognitiveReport)."""

    scan_id: int | None
    findings: list[Finding]
    sources: list[str]
    analysis: str = ""
    remediation_generated: bool = False
    perspective: Perspective = Perspective.INTERNAL
    ai_used: bool = False
    decisions: list = field(default_factory=list)
    skipped_tools: list[str] = field(default_factory=list)


def run_log_analysis(
    paths: list[str],
    *,
    registry: PluginRegistry | None = None,
    store: FindingStore | None = None,
    risk: RiskScorer | None = None,
    provider=None,
    engagement: str = "blue:log-analysis",
) -> BlueReport:
    """Roda o plugin ``log-analysis`` sobre ``paths`` e persiste como um scan.

    Com ``provider``, dispara a análise e o plano de remediação da IA (mesmo
    downstream do Red). Sem findings, não chama a IA (nada a analisar)."""
    registry = registry if registry is not None else PluginRegistry.discover()
    spec = registry.get(_LOG_ANALYSIS)
    if spec is None or not spec.available():
        raise RuntimeError(
            "Plugin 'log-analysis' indisponível. Rode `eigan doctor` para diagnosticar."
        )

    findings: list[Finding] = []
    for p in paths:
        produced = spec.scan(p)
        for f in produced:
            f.perspective = Perspective.INTERNAL  # Blue = inside-out (defensivo)
        findings.extend(produced)

    findings = deduplicate(findings)
    if risk is not None:
        findings = risk.score(findings)
    findings.sort(key=lambda f: (f.risk_rank, f.severity.rank), reverse=True)

    scan_id: int | None = None
    analysis = ""
    remediated = False
    if store is not None:
        scan_id = store.create_scan(engagement, "internal/blue", list(paths))
        store.add_findings(scan_id, findings)
        store.finish_scan(scan_id)
        if findings and provider is not None:
            from ..analysis.engine import analyze_and_store, remediate_and_store

            analysis = analyze_and_store(store, scan_id, provider=provider) or ""
            remediated = bool(remediate_and_store(store, scan_id, provider=provider))

    log.info(
        "blue log-analysis concluído",
        extra={"event": "blue_done", "sources": len(paths), "findings": len(findings)},
    )
    return BlueReport(
        scan_id=scan_id,
        findings=findings,
        sources=list(paths),
        analysis=analysis,
        remediation_generated=remediated,
        ai_used=bool(provider is not None and findings),
    )
