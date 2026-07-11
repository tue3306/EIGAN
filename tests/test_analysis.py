"""Testes das análises pós-scan: inventário (Blue), ATT&CK (Purple), conformidade."""

from eigan.analysis.attack import ENTERPRISE_TACTICS, map_attack
from eigan.analysis.compliance import assess_compliance
from eigan.analysis.inventory import build_inventory, summarize
from eigan.findings.schema import Finding, Severity
from eigan.perspective import Perspective


def _f(tool, asset, **kw):
    return Finding(
        title=f"{tool}:{asset}",
        severity=Severity.INFO,
        affected_asset=asset,
        source_tool=tool,
        **kw,
    )


# ── inventário ──────────────────────────────────────────────────────────────
def test_inventory_aggregates_ports_and_web():
    findings = [
        _f("nmap", "10.0.0.5:80"),
        _f("nmap", "10.0.0.5:443"),
        _f("httpx", "https://10.0.0.5/"),
    ]
    inv = build_inventory(findings)
    assert len(inv) == 1
    a = inv[0]
    assert a.host == "10.0.0.5"
    assert a.ports == ["80", "443"]
    assert a.web_endpoints == ["https://10.0.0.5/"]
    assert summarize(inv)["with_open_ports"] == 1


def test_inventory_cross_perspective():
    ext = _f("nuclei", "site:443")
    ext.perspective = Perspective.EXTERNAL
    intr = _f("nmap", "site:445")
    intr.perspective = Perspective.INTERNAL
    inv = build_inventory([ext, intr])
    assert summarize(inv)["cross_perspective"] == 1


# ── ATT&CK (Purple) ─────────────────────────────────────────────────────────
def test_attack_maps_known_techniques_and_reports_gap():
    findings = [
        _f("nmap", "h:80", attack_technique="T1046"),  # Discovery
        _f("subfinder", "sub.h", attack_technique="T1590"),  # Reconnaissance
    ]
    cov = map_attack(findings)
    tactics = {h.tactic for h in cov.hits}
    assert "Discovery" in tactics and "Reconnaissance" in tactics
    assert set(cov.tactics_covered) <= set(ENTERPRISE_TACTICS)
    # táticas sem sinal aparecem no gap (ex.: Impact).
    assert "Impact" in cov.tactics_gap


def test_attack_unknown_technique_is_unmapped_not_invented():
    # técnica fora do catálogo curado NÃO vira tática inventada.
    cov = map_attack([_f("x", "h", attack_technique="T9999")])
    assert cov.unmapped == ["T9999"]
    assert cov.hits == []


# ── conformidade (Blue) ─────────────────────────────────────────────────────
def test_compliance_maps_cwe_to_references():
    findings = [_f("nuclei", "http://h/", cwe="CWE-89"), _f("nmap", "h:80")]  # sem CWE => unmapped
    rep = assess_compliance(findings)
    assert rep.unmapped == 1
    assert rep.indicative is True
    assert any("OWASP" in fw for fw in rep.frameworks)
    assert rep.items[0].refs[0].url.startswith("https://")
