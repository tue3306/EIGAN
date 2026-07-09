"""Testes do Correlation Engine — visão por ativo + cadeia de ataque."""

from vulnforge.engine.correlation import correlate_assets
from vulnforge.findings.schema import CVSS, Finding, Severity
from vulnforge.perspective import Perspective


def _f(tool, asset, sev=Severity.INFO, **kw):
    return Finding(title=f"{tool} em {asset}", severity=sev, affected_asset=asset,
                   source_tool=tool, **kw)


def test_correlates_by_host_and_builds_chain():
    findings = [
        _f("nmap", "10.0.0.5:80"),
        _f("httpx", "http://10.0.0.5/"),
        _f("nuclei", "http://10.0.0.5/app", sev=Severity.HIGH,
           cvss=CVSS(version="3.1", score=8.8)),
    ]
    corr = correlate_assets(findings)
    assert len(corr) == 1
    asset = corr[0]
    assert asset.asset == "10.0.0.5"
    # cadeia com 3 papéis, ordenada exposição→superfície→vulnerabilidade.
    assert len(asset.attack_chain) == 3
    assert "Porta" in asset.attack_chain[0]
    assert "Vulnerabilidade" in asset.attack_chain[-1]


def test_no_chain_when_single_role():
    findings = [_f("nmap", "10.0.0.5:80"), _f("nmap", "10.0.0.5:443")]
    corr = correlate_assets(findings)
    # só exposição (um papel) => sem cadeia (não inventa progressão).
    assert corr[0].attack_chain == []


def test_cross_perspective_flag():
    ext = _f("nuclei", "http://site/", sev=Severity.MEDIUM)
    ext.perspective = Perspective.EXTERNAL
    intr = _f("nmap", "site:445")
    intr.perspective = Perspective.INTERNAL
    corr = correlate_assets([ext, intr])
    assert corr[0].cross_perspective is True
    assert set(corr[0].perspectives) == {"external", "internal"}


def test_sorted_by_risk():
    low = _f("nmap", "a:80")
    high = _f("nuclei", "b:443", sev=Severity.CRITICAL, cvss=CVSS(version="3.1", score=9.8))
    corr = correlate_assets([low, high])
    assert corr[0].asset == "b"  # maior risco primeiro
