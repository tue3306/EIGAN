"""Testes da camada de Validação (§16 anti-falso-positivo, confiança explícita).

Provam a regra de ouro: a confiança só SOBE com prova real (PoC ativa ou
corroboração por ≥2 fontes) e NUNCA é fabricada nem rebaixa o que a ferramenta
afirmou.
"""

from __future__ import annotations

from eigan.analysis.validation import Validator
from eigan.findings.schema import Confidence, Finding, Severity


def _f(tool: str, *, confidence=Confidence.TENTATIVE, correlated=None) -> Finding:
    return Finding(
        title="SQLi em id",
        severity=Severity.HIGH,
        affected_asset="http://alvo/app?id=1",
        source_tool=tool,
        confidence=confidence,
        correlated_sources=list(correlated or []),
    )


def test_active_validator_tool_is_confirmed():
    v = Validator().assess(_f("sqlmap"))
    assert v.confidence is Confidence.CONFIRMED and v.validated is True
    assert "PoC" in v.rationale
    assert Validator().assess(_f("dalfox")).confidence is Confidence.CONFIRMED


def test_corroboration_upgrades_to_firm():
    v = Validator().assess(_f("nuclei", correlated=["nikto"]))
    assert v.confidence is Confidence.FIRM and v.validated is True
    assert "2 fontes" in v.rationale


def test_corroboration_never_downgrades_confirmed():
    # já CONFIRMED por outra via + corroborado → não cai para FIRM (nunca rebaixa).
    v = Validator().assess(_f("nuclei", confidence=Confidence.CONFIRMED, correlated=["nikto"]))
    assert v.confidence is Confidence.CONFIRMED


def test_single_source_preserves_reported_confidence():
    v = Validator().assess(_f("whatweb", confidence=Confidence.TENTATIVE))
    assert v.confidence is Confidence.TENTATIVE and v.validated is False


def test_single_source_does_not_fabricate_confirmation():
    # fonte única não vira CONFIRMED só porque a ferramenta disse — sem prova/corrob.
    v = Validator().assess(_f("nikto", confidence=Confidence.TENTATIVE))
    assert v.confidence is not Confidence.CONFIRMED


def test_apply_mutates_and_summarizes():
    findings = [
        _f("sqlmap"),  # → CONFIRMED, validated
        _f("nuclei", correlated=["nikto"]),  # → FIRM, validated
        _f("whatweb"),  # → TENTATIVE, não validado
    ]
    summary = Validator().apply(findings)
    assert [f.confidence for f in findings] == [
        Confidence.CONFIRMED,
        Confidence.FIRM,
        Confidence.TENTATIVE,
    ]
    assert summary.total == 3 and summary.validated == 2
    assert summary.by_confidence == {"confirmed": 1, "firm": 1, "tentative": 1}


def test_summarize_is_read_only():
    findings = [_f("sqlmap")]
    before = findings[0].confidence
    Validator().summarize(findings)
    assert findings[0].confidence is before  # summarize não muta
