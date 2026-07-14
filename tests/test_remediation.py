"""Plano de Remediação por IA (o que arrumar + como) — ai/remediation + integração.

Cobre: parse estruturado (JSON), fallback textual, degradação sem json_mode,
persistência no store e render da seção nos relatórios HTML/Markdown. Usa um
provedor fake — sem rede/chave (§14: testes hermeticamente locais)."""

from __future__ import annotations

from pathlib import Path

from eigan.ai.provider import Enricher
from eigan.ai.remediation import (
    RemediationItem,
    RemediationPlan,
    plan_from_json,
    plan_to_json,
    remediation_plan,
)
from eigan.findings.schema import Finding, Severity
from eigan.findings.store import FindingStore
from eigan.knowledge.loader import KnowledgeBase
from eigan.report.deterministic import ReportGenerator
from eigan.report.markdown import render_markdown

_KB = Path(__file__).resolve().parents[1] / "knowledge" / "skills"

_GOOD_JSON = (
    '{"items":[{"title":"Porta SSH exposta","asset":"1.2.3.4:22","severity":"medium",'
    '"what":"Restringir SSH","how":"Firewall allowlist + fail2ban + só chaves",'
    '"priority":"P2","effort":"baixo"}],"summary":"Priorize a exposição de rede."}'
)


class _FakeProv:
    """Provedor mínimo: devolve ``out`` e registra se pediram json_mode."""

    def __init__(self, out: str, *, accept_json_mode: bool = True) -> None:
        self.out = out
        self.accept_json_mode = accept_json_mode
        self.asked_json_mode = False

    def complete(self, system: str, user: str, json_mode: bool = False) -> str:
        if json_mode and not self.accept_json_mode:
            raise TypeError("json_mode não suportado")
        self.asked_json_mode = json_mode
        return self.out


def test_remediation_parses_structured_json():
    plan = remediation_plan("ctx", provider=_FakeProv(_GOOD_JSON))
    assert len(plan.items) == 1
    it = plan.items[0]
    assert it.title == "Porta SSH exposta"
    assert it.priority == "P2" and it.effort == "baixo"
    assert plan.summary.startswith("Priorize")
    assert plan.ai_generated is True
    assert not plan.is_empty()


def test_remediation_falls_back_to_text_when_not_json():
    plan = remediation_plan("ctx", provider=_FakeProv("Texto livre, sem JSON."))
    assert plan.items == []
    assert plan.text == "Texto livre, sem JSON."
    assert not plan.is_empty()


def test_remediation_empty_output_is_empty_plan():
    plan = remediation_plan("ctx", provider=_FakeProv(""))
    assert plan.is_empty()


def test_remediation_degrades_when_provider_rejects_json_mode():
    # Provedor antigo sem o kwarg json_mode → cai para complete(system, user).
    plan = remediation_plan("ctx", provider=_FakeProv(_GOOD_JSON, accept_json_mode=False))
    assert len(plan.items) == 1


def test_plan_json_roundtrip_and_none():
    plan = RemediationPlan(
        items=[RemediationItem(title="x", what="y", how="z", priority="P1")],
        summary="s",
    )
    blob = plan_to_json(plan)
    back = plan_from_json(blob)
    assert back is not None and len(back.items) == 1 and back.items[0].priority == "P1"
    assert plan_from_json(None) is None
    assert plan_from_json("{}") is None  # vazio → None
    assert plan_from_json("não é json") is None


def test_store_persists_remediation():
    store = FindingStore(":memory:")
    sid = store.create_scan("demo", "external/standard", ["ex.com"])
    assert store.get_remediation(sid) is None
    store.set_remediation(sid, plan_to_json(RemediationPlan(summary="ok")))
    assert store.get_remediation(sid) is not None
    store.close()


def _sample_findings() -> list[Finding]:
    return [
        Finding(
            title="Cifras fracas",
            severity=Severity.LOW,
            affected_asset="ex.com:443",
            source_tool="testssl",
        ),
    ]


def test_report_html_includes_remediation_section():
    plan = plan_from_json(
        plan_to_json(
            RemediationPlan(
                items=[
                    RemediationItem(
                        title="Cifras fracas",
                        asset="ex.com:443",
                        what="Desabilitar TLS antigo",
                        how="ssl_protocols TLSv1.2 TLSv1.3",
                        priority="P1",
                        effort="médio",
                    )
                ]
            )
        )
    )
    gen = ReportGenerator(Enricher(KnowledgeBase(_KB), provider=None), tool_version="0.0.0")
    for style in ("technical", "executive"):
        html = gen.render_html(
            _sample_findings(),
            engagement="demo",
            targets=["ex.com"],
            style=style,
            ai_remediation=plan,
        )
        assert "Plano de remediação priorizado (IA)" in html
        assert "Desabilitar TLS antigo" in html


def test_report_html_omits_section_without_plan():
    gen = ReportGenerator(Enricher(KnowledgeBase(_KB), provider=None), tool_version="0.0.0")
    html = gen.render_html(_sample_findings(), engagement="demo", targets=["ex.com"])
    assert "Plano de remediação priorizado (IA)" not in html


def test_markdown_includes_remediation_table():
    plan = RemediationPlan(
        items=[
            RemediationItem(
                title="Cifras fracas",
                what="Desabilitar TLS antigo",
                how="ssl_protocols TLSv1.2",
                priority="P1",
                effort="médio",
            )
        ],
        summary="Priorize TLS.",
    )
    md = render_markdown(
        _sample_findings(), engagement="demo", targets=["ex.com"], ai_remediation=plan
    )
    assert "Plano de remediação priorizado (IA)" in md
    assert "Desabilitar TLS antigo" in md
    assert "| Prio. |" in md  # tabela
