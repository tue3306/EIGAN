"""Merge/correlação ENTRE scans (ex.: vários scans simultâneos de alvos distintos).

Junta os findings de vários scans num relatório unificado: deduplica e correlaciona
por ``fingerprint`` (a MESMA vuln vinda de scans diferentes vira um só finding com
múltiplas fontes) e ordena por risco. Base da visão consolidada e da correlação da
IA (que enxerga a superfície inteira de uma vez, não scan a scan).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ..ai.context import build_scan_context, severity_counts
from ..findings.dedup import deduplicate
from ..findings.schema import Finding

if TYPE_CHECKING:
    from ..findings.store import FindingStore


def merge_findings(store: "FindingStore", scan_ids: list[int]) -> tuple[list[Finding], dict]:
    """Findings unificados (dedup entre scans) + metadados (alvos, por-scan)."""
    combined: list[Finding] = []
    per_scan: dict[int, int] = {}
    targets: list[str] = []
    for sid in scan_ids:
        meta = store.get_scan(sid)
        if not meta:
            continue
        fs = store.get_findings(sid)
        per_scan[sid] = len(fs)
        combined += fs
        try:
            targets += json.loads(meta.get("targets") or "[]")
        except (json.JSONDecodeError, TypeError):
            pass
    merged = deduplicate(combined)
    merged.sort(key=lambda f: (f.risk.score if f.risk else 0.0, f.severity.rank), reverse=True)
    return merged, {"per_scan": per_scan, "targets": sorted(set(targets))}


def merge_summary(store: "FindingStore", scan_ids: list[int]) -> dict:
    """Resumo serializável da correlação entre scans (para a API/dashboard)."""
    merged, meta = merge_findings(store, scan_ids)
    return {
        "scan_ids": scan_ids,
        "targets": meta["targets"],
        "per_scan": meta["per_scan"],
        "count": len(merged),
        "severity": severity_counts(merged),
        "correlated": sum(1 for f in merged if f.correlated_sources),
        "findings": [f.model_dump(mode="json") for f in merged],
    }


def merge_context(store: "FindingStore", scan_ids: list[int]) -> str:
    """Contexto grounded da superfície unificada — para a correlação da IA."""
    merged, meta = merge_findings(store, scan_ids)
    return build_scan_context(
        merged,
        engagement=f"correlação de {len(scan_ids)} scans",
        targets=meta["targets"],
        profile="merge",
    )
