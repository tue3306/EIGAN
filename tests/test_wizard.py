"""Testes dos helpers puros/apresentacionais do wizard (``eigan.cli.wizard``).

O fluxo interativo completo depende de ``click.prompt``; aqui cobrimos as partes
determinísticas: contagem por severidade, a barra colorida e o resumo pós-scan.
"""

from __future__ import annotations

from types import SimpleNamespace

from eigan.cli import wizard
from eigan.findings.schema import Finding, Severity
from eigan.perspective import Perspective


def _f(sev: Severity, title: str = "Vuln") -> Finding:
    return Finding(
        title=title,
        severity=sev,
        affected_asset="host:80",
        source_tool="nuclei",
    )


def test_count_by_severity_covers_all_levels():
    findings = [_f(Severity.CRITICAL), _f(Severity.HIGH), _f(Severity.HIGH), _f(Severity.INFO)]
    counts = wizard._count_by_severity(findings)
    assert counts[Severity.CRITICAL] == 1
    assert counts[Severity.HIGH] == 2
    assert counts[Severity.INFO] == 1
    assert counts[Severity.LOW] == 0  # níveis ausentes ainda aparecem com zero


def test_count_by_severity_empty():
    counts = wizard._count_by_severity([])
    assert set(counts) == set(Severity)
    assert sum(counts.values()) == 0


def test_severity_bar_lists_every_label():
    bar = wizard._severity_bar(wizard._count_by_severity([_f(Severity.CRITICAL)]))
    for _sev, label, _color in wizard._SEV_DISPLAY:
        assert label in bar


def test_print_results_shows_counts_and_titles(capsys):
    report = SimpleNamespace(
        scan_id=7,
        perspective=Perspective.UNIFIED,
        findings=[_f(Severity.CRITICAL, "RCE"), _f(Severity.LOW, "Banner")],
        skipped_tools=[],
    )
    wizard._print_results(report)
    out = capsys.readouterr().out
    assert "Scan #7" in out
    assert "CRÍTICA" in out and "RCE" in out


def test_print_results_reports_skipped_tools(capsys):
    report = SimpleNamespace(
        scan_id=1,
        perspective=Perspective.UNIFIED,
        findings=[],
        skipped_tools=["nmap", "nuclei"],
    )
    wizard._print_results(report)
    out = capsys.readouterr().out
    assert "indisponíveis" in out and "nmap" in out
