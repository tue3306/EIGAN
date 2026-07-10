"""Testes dos pilares reais da Parte 4 (ADR-0008): memória/diff e remediação.

Ambos são **determinísticos** (não dependem de IA) e respeitam as fronteiras:
o diff é puro por fingerprint; a remediação é sugestão revisável, nunca aplicada.
"""

from __future__ import annotations

import yaml

from vulnforge.analysis.diff import diff_findings
from vulnforge.findings.schema import Finding, Severity
from vulnforge.findings.store import FindingStore
from vulnforge.report.remediation import generate, generate_all


def _f(title: str, asset: str, tool: str = "nmap", sev: Severity = Severity.MEDIUM) -> Finding:
    return Finding(title=title, severity=sev, affected_asset=asset, source_tool=tool)


# --------------------------------------------------------------------------- #
# Pilar 2 — memória / diff entre scans
# --------------------------------------------------------------------------- #
def test_diff_classifies_new_resolved_persisting():
    prev = [_f("Porta 22 aberta", "h:22"), _f("Porta 80 aberta", "h:80")]
    cur = [_f("Porta 80 aberta", "h:80"), _f("Porta 443 aberta", "h:443")]
    d = diff_findings(prev, cur, previous_scan_id=1, current_scan_id=2)
    assert [f.affected_asset for f in d.new] == ["h:443"]
    assert [f.affected_asset for f in d.resolved] == ["h:22"]
    assert [f.affected_asset for f in d.persisting] == ["h:80"]
    assert d.changed is True


def test_diff_detects_new_services():
    prev = [_f("Porta 80 aberta", "h:80")]
    cur = [_f("Porta 80 aberta", "h:80"), _f("Porta 445 aberta", "h:445")]
    d = diff_findings(prev, cur)
    assert "h:445" in d.new_services
    assert "h:80" not in d.new_services


def test_diff_first_scan_summary():
    d = diff_findings([], [_f("x", "h:80")], previous_scan_id=None, current_scan_id=5)
    assert "Primeira vez" in d.summary()


def test_diff_no_change_summary():
    same = [_f("Porta 80 aberta", "h:80")]
    d = diff_findings(same, list(same), previous_scan_id=3, current_scan_id=4)
    assert d.changed is False
    assert "Sem mudanças" in d.summary()


def test_store_find_previous_scan(tmp_path):
    store = FindingStore(tmp_path / "t.db")
    s1 = store.create_scan("eng", "external/standard", ["example.com"])
    store.finish_scan(s1)
    s2 = store.create_scan("eng", "external/standard", ["example.com"])
    store.finish_scan(s2)
    s3 = store.create_scan("eng", "external/standard", ["outro.com"])  # alvo diferente
    store.finish_scan(s3)
    assert store.find_previous_scan(s2) == s1
    assert store.find_previous_scan(s1) is None  # primeira vez
    assert store.find_previous_scan(s3) is None  # sem alvo em comum
    store.close()


# --------------------------------------------------------------------------- #
# Pilar 6 — auto remediation (Ansible, revisável)
# --------------------------------------------------------------------------- #
def test_remediation_for_exposed_database_port():
    art = generate(_f("Porta aberta 3306/tcp (mysql)", "db.example.com:3306"))
    assert art is not None
    assert art.format == "ansible"
    assert "3306" in art.content and "MySQL" in art.content
    # segurança: é sugestão revisável, nunca auto-aplicada.
    assert art.reviewable is True
    assert "REVISE antes de aplicar" in art.content
    # o playbook é YAML válido (após o cabeçalho de comentário).
    docs = list(yaml.safe_load_all(art.content))
    assert any(isinstance(doc, list) for doc in docs)  # lista de plays


def test_remediation_for_security_headers():
    art = generate(_f("Falta cabeçalho HSTS (Security Header ausente)", "https://h/"))
    assert art is not None
    assert "Strict-Transport-Security" in art.content


def test_remediation_returns_none_without_template():
    # finding sem template não fabrica playbook genérico (scaffold honesto).
    assert generate(_f("Informação de banner", "h:12345")) is None


def test_generate_all_splits_covered_and_uncovered():
    findings = [
        _f("Porta aberta 445/tcp (smb)", "h:445"),
        _f("Banner informativo", "h:9999"),
    ]
    artifacts, uncovered = generate_all(findings)
    assert len(artifacts) == 1
    assert len(uncovered) == 1
    assert uncovered[0].affected_asset == "h:9999"
