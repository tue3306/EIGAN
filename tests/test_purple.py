"""Purple — correlação ataque×detecção: covered / gap (ponto cego) / detection_only."""

from __future__ import annotations

from eigan.analysis.purple import (
    correlate,
    correlate_findings,
    purple_context,
    split_findings,
)
from eigan.findings.schema import Finding, Severity

_CAT = {
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access", "url": "u"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "url": "u"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery", "url": "u"},
}


def _f(tool: str, tech: str) -> Finding:
    return Finding(
        title=f"{tool}:{tech}",
        severity=Severity.MEDIUM,
        affected_asset="x",
        source_tool=tool,
        attack_technique=tech,
    )


def test_covered_gap_and_detection_only():
    red = [_f("nuclei", "T1190"), _f("nmap", "T1046")]  # atacou T1190 e T1046
    blue = [_f("log-analysis", "T1190"), _f("log-analysis", "T1110")]  # detecta T1190 e T1110
    rep = correlate(red, blue, catalog=_CAT)
    assert rep.covered == ["T1190"]  # atacado E detectado
    assert rep.gaps == ["T1046"]  # atacado SEM detecção (ponto cego)
    assert rep.detection_only == ["T1110"]  # detecção sem ataque correlato
    assert rep.coverage_pct == 50.0  # 1 coberto de 2 atacados
    # gaps aparecem primeiro (mais acionável)
    assert rep.correlations[0].status == "gap"


def test_split_findings_by_tool():
    mixed = [_f("nuclei", "T1190"), _f("log-analysis", "T1110")]
    red, blue = split_findings(mixed)
    assert [x.source_tool for x in red] == ["nuclei"]
    assert [x.source_tool for x in blue] == ["log-analysis"]


def test_correlate_findings_convenience():
    mixed = [_f("nuclei", "T1190"), _f("log-analysis", "T1190"), _f("nmap", "T1046")]
    rep = correlate_findings(mixed, catalog=_CAT)
    assert "T1190" in rep.covered and "T1046" in rep.gaps


def test_coverage_100_when_all_detected():
    rep = correlate([_f("nuclei", "T1190")], [_f("log-analysis", "T1190")], catalog=_CAT)
    assert rep.coverage_pct == 100.0 and rep.gaps == []


def test_no_red_gives_zero_denominator_not_crash():
    rep = correlate([], [_f("log-analysis", "T1110")], catalog=_CAT)
    assert rep.coverage_pct == 0.0
    assert rep.detection_only == ["T1110"] and rep.gaps == []


def test_purple_context_lists_gaps():
    red = [_f("nuclei", "T1046")]
    ctx = purple_context(correlate(red, [], catalog=_CAT))
    assert "PONTOS CEGOS" in ctx and "T1046" in ctx
