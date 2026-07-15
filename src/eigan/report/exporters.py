"""Exporters de findings — JSON, CSV e SARIF. **Todos funcionam sem IA** (§11).

Formatos de máquina para integração (CI, dashboards, GitHub code scanning).
Puros e determinísticos: recebem findings + metadados e devolvem texto. Nenhum
depende de chave de API.

SARIF: formato 2.1.0 (OASIS) — estrutura mínima confirmada na especificação
oficial (version + runs + tool.driver + results[].level ∈ note|warning|error).
"""

from __future__ import annotations

import csv
import io
import json

from ..findings.schema import Finding, Severity

# Severidade normalizada → nível SARIF (spec 3.27.10).
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_CSV_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: str) -> str:
    """Neutraliza *CSV/formula injection* (CWE-1236) em campos textuais.

    Planilhas (Excel/Sheets/LibreOffice) executam células que começam com
    ``= + - @`` (ou tab/CR) como fórmula. Como títulos/ativos vêm da saída de
    ferramentas — e um alvo malicioso pode plantar, ex., um título HTTP
    ``=cmd|'/c calc'!A1`` — prefixamos uma aspa simples para forçar texto. Não
    altera o significado para SIEM, só desarma a execução em planilha.
    """
    s = str(value)
    return "'" + s if s[:1] in _CSV_FORMULA_TRIGGERS else s


_CSV_COLUMNS = [
    "title",
    "severity",
    "risk_score",
    "epss",
    "epss_verified",
    "kev",
    "kev_verified",
    "perspective",
    "affected_asset",
    "cwe",
    "owasp",
    "attack_technique",
    "source_tool",
    "confidence",
    "cvss_version",
    "cvss_score",
    "references",
]


def to_json(findings: list[Finding], *, meta: dict | None = None) -> str:
    """JSON completo: metadados + sumário + findings normalizados (com risco)."""
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    payload = {
        "meta": meta or {},
        "summary": counts,
        "count": len(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_csv(findings: list[Finding]) -> str:
    """CSV achatado (uma linha por finding) para planilha/SIEM."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        risk = f.risk
        writer.writerow(
            {
                # campos textuais vêm de saída de ferramenta → neutraliza fórmula (CWE-1236)
                "title": _csv_safe(f.title),
                "severity": f.severity.value,
                "risk_score": risk.score if risk else "",
                "epss": (risk.epss if risk and risk.epss is not None else ""),
                "epss_verified": (risk.epss_verified if risk else ""),
                "kev": (risk.kev if risk else ""),
                "kev_verified": (risk.kev_verified if risk else ""),
                "perspective": f.perspective.value,
                "affected_asset": _csv_safe(f.affected_asset),
                "cwe": _csv_safe(f.cwe or ""),
                "owasp": _csv_safe(f.owasp or ""),
                "attack_technique": _csv_safe(f.attack_technique or ""),
                "source_tool": _csv_safe(f.source_tool),
                "confidence": f.confidence.value,
                "cvss_version": f.cvss.version if f.cvss else "",
                "cvss_score": f.cvss.score if f.cvss else "",
                "references": _csv_safe(" ".join(f.references)),
            }
        )
    return buf.getvalue()


def to_sarif(
    findings: list[Finding], *, tool_version: str = "0.0.0", meta: dict | None = None
) -> str:
    """SARIF 2.1.0 — para GitHub code scanning e ferramentas compatíveis."""
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        rule_id = f.cwe or f.attack_technique or f.source_tool
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("-", "_"),
                "shortDescription": {"text": f.title[:120]},
                "properties": {k: v for k, v in (("cwe", f.cwe), ("owasp", f.owasp)) if v},
            }
        props: dict[str, object] = {
            "severity": f.severity.value,
            "perspective": f.perspective.value,
            "source_tool": f.source_tool,
            "confidence": f.confidence.value,
        }
        if f.cvss:
            props["cvss"] = f"{f.cvss.version}:{f.cvss.score}"
        if f.risk:
            props["risk_score"] = f.risk.score
            if f.risk.epss_verified:
                props["epss"] = f.risk.epss
            if f.risk.kev_verified:
                props["kev"] = f.risk.kev
        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f.title + (f" — {f.description}" if f.description else "")},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": f.affected_asset}}}
                ],
                "properties": props,
            }
        )

    log = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "EIGAN",
                        "version": tool_version,
                        "informationUri": "https://github.com/tue3306/EIGAN",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": meta or {},
            }
        ],
    }
    return json.dumps(log, indent=2, ensure_ascii=False)
