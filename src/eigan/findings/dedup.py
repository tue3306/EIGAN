"""Deduplicação e correlação de findings.

Mesma vulnerabilidade reportada por ferramentas diferentes (mesmo `fingerprint`)
é fundida em um único finding com múltiplas evidências e a maior severidade
observada. Como o `fingerprint` inclui a perspectiva, findings de perspectivas
diferentes NUNCA são fundidos aqui — a correlação entre perspectivas é feita na
camada de asset por :func:`correlate_by_asset`, preservando a origem.
Determinístico — não depende de IA (CLAUDE.md §5/§7).
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
            # Concatena com separador SEM `.strip("\n-")`: aquele strip comia
            # traços/quebras LEGÍTIMOS do conteúdo (ex.: "-----END CERTIFICATE-----"),
            # corrompendo a evidência que vai para o relatório (§12).
            base.evidence = f"{base.evidence}\n---\n{f.evidence}" if base.evidence else f.evidence
        # referências únicas
        for ref in f.references:
            if ref not in base.references:
                base.references.append(ref)
        # first_seen = o MAIS ANTIGO observado (semântica de "primeira vez visto");
        # last_seen = o mais recente. Antes só last_seen era fundido.
        base.first_seen = min(base.first_seen, f.first_seen)
        base.last_seen = max(base.last_seen, f.last_seen)

    return list(merged.values())


def correlate_by_asset(findings: list[Finding]) -> dict[str, dict[str, list[Finding]]]:
    """Agrupa findings por ativo e, dentro dele, por perspectiva — sem fundir.

    Serve à camada de asset (Parte 1 do escopo): permite comparar/mesclar o que
    foi visto de fora × de dentro para o mesmo host, mantendo total
    rastreabilidade da origem (perspectiva + ferramenta de cada finding).
    """
    out: dict[str, dict[str, list[Finding]]] = {}
    for f in findings:
        out.setdefault(f.affected_asset, {}).setdefault(f.perspective.value, []).append(f)
    return out
