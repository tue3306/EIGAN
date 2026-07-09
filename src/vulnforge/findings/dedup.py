"""Deduplicação e correlação de findings.

Mesma vulnerabilidade reportada por ferramentas diferentes (mesmo `fingerprint`)
é fundida em um único finding com múltiplas evidências e a maior severidade
observada. Determinístico — não depende de IA (CLAUDE.md §5/§7).
"""

from __future__ import annotations

from .schema import Finding


def deduplicate(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for f in findings:
        key = f.fingerprint
        if key not in merged:
            merged[key] = f.model_copy(deep=True)
            continue

        base = merged[key]
        # mantém a maior severidade
        if f.severity.rank > base.severity.rank:
            base.severity = f.severity
        # acumula fontes/evidências
        if f.source_tool not in base.correlated_sources and f.source_tool != base.source_tool:
            base.correlated_sources.append(f.source_tool)
        if f.evidence and f.evidence not in base.evidence:
            base.evidence = (base.evidence + "\n---\n" + f.evidence).strip("\n-")
        # referências únicas
        for ref in f.references:
            if ref not in base.references:
                base.references.append(ref)
        base.last_seen = max(base.last_seen, f.last_seen)

    return list(merged.values())
