"""Testes do Risk Engine e dos feeds — foco na regra anti-invenção (§5/ADR-0002).

Nenhum teste toca a rede: os feeds são injetados em memória ou via *getter* falso.
"""

import json

from vulnforge.engine.feeds import FeedCache
from vulnforge.engine.risk import RiskScorer, cve_ids
from vulnforge.findings.schema import CVSS, Finding, Severity


def _finding(**kw) -> Finding:
    base = dict(title="RCE", severity=Severity.HIGH, affected_asset="h:443", source_tool="nuclei")
    base.update(kw)
    return Finding(**base)


def test_cve_extraction_from_references():
    f = _finding(references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"])
    assert cve_ids(f) == {"CVE-2021-44228"}


def test_kev_and_epss_verified_raise_score():
    feeds = FeedCache(
        kev_cves={"CVE-2021-44228"},
        kev_meta={"dateReleased": "2026-07-07"},
        epss_scores={"CVE-2021-44228": 0.9999},
        epss_meta={"date": "2026-07-08"},
    )
    f = _finding(
        cvss=CVSS(version="3.1", score=10.0),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    )
    RiskScorer(feeds).score([f])
    assert f.risk.kev is True and f.risk.kev_verified is True
    assert f.risk.epss_verified is True and abs(f.risk.epss - 0.9999) < 1e-6
    assert f.risk.exploit_available is True
    assert f.risk.score >= 95.0
    assert "CISA KEV 2026-07-07" in f.risk.provenance["kev"]
    assert "FIRST.org EPSS 2026-07-08" in f.risk.provenance["epss"]


def test_no_feeds_marks_unverified_never_fabricates():
    f = _finding(
        cvss=CVSS(version="3.1", score=7.0),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-9999"],
    )
    RiskScorer(None).score([f])
    # sem feeds: EPSS/KEV NÃO viram fato.
    assert f.risk.epss is None and f.risk.epss_verified is False
    assert f.risk.kev is False and f.risk.kev_verified is False
    assert "UNVERIFIED" in f.risk.provenance["kev"]
    assert "UNVERIFIED" in f.risk.provenance["epss"]
    # score usa só o verificável (CVSS 7.0 -> base 70).
    assert f.risk.score == 70.0


def test_kev_absence_is_verified_when_catalog_loaded():
    # catálogo KEV carregado, CVE não consta => kev=False, mas VERIFICADO.
    feeds = FeedCache(kev_cves=set(), kev_meta={"dateReleased": "2026-07-07"})
    f = _finding(references=["https://nvd.nist.gov/vuln/detail/CVE-2024-1111"])
    RiskScorer(feeds).score([f])
    assert f.risk.kev is False and f.risk.kev_verified is True


def test_online_epss_uses_getter_not_network():
    fetched = {}

    def fake_getter(url, timeout=30):
        fetched["url"] = url
        return json.dumps(
            {
                "data": [
                    {
                        "cve": "CVE-2021-1234",
                        "epss": "0.5",
                        "percentile": "0.9",
                        "date": "2026-07-08",
                    }
                ]
            }
        ).encode()

    feeds = FeedCache(epss_scores={}, epss_meta={})
    f = _finding(references=["https://nvd.nist.gov/vuln/detail/CVE-2021-1234"])
    RiskScorer(feeds, online=True, getter=fake_getter).score([f])
    assert "CVE-2021-1234" in fetched["url"]
    assert f.risk.epss_verified is True and abs(f.risk.epss - 0.5) < 1e-6


def test_update_kev_parses_catalog_and_records_integrity(tmp_path):
    payload = json.dumps(
        {
            "catalogVersion": "2026.07.07",
            "dateReleased": "2026-07-07T00:00:00Z",
            "vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": "CVE-2020-1472"}],
        }
    ).encode()
    feeds = FeedCache(cache_dir=tmp_path / "feeds")
    feeds.update_kev(getter=lambda url, timeout=30: payload)
    assert feeds.kev_cves == {"CVE-2021-44228", "CVE-2020-1472"}
    assert len(feeds.kev_meta["sha256"]) == 64
    assert feeds.kev_meta["count"] == 2
    # persistiu e recarrega igual.
    reloaded = FeedCache.load(tmp_path / "feeds")
    assert reloaded.kev_cves == feeds.kev_cves
