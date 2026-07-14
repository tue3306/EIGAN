"""Testes dos detectores de log-analysis (Blue) — sobre amostras reais de log."""

from __future__ import annotations

from plugins.blue.log_analysis.parser import analyze_logs
from plugins.blue.log_analysis.runner import LogAnalysisRunner

_AUTH_BRUTE_SUCCESS = "\n".join(
    [
        f"Jul 14 sshd[{i}]: Failed password for root from 203.0.113.9 port 5{i} ssh2"
        for i in range(6)
    ]
    + ["Jul 14 sshd[99]: Accepted password for root from 203.0.113.9 port 6000 ssh2"]
)
_AUTH_BRUTE_ONLY = "\n".join(
    f"Jul 14 sshd[{i}]: Failed password for invalid user admin from 198.51.100.5 port 5{i} ssh2"
    for i in range(7)
)
_ACCESS = "\n".join(
    [
        '198.51.100.7 - - [14/Jul/2026:02:00:01 +0000] "GET /?id=1+union+select+1,2 '
        'HTTP/1.1" 200 12 "-" "sqlmap/1.7"',
        '198.51.100.7 - - [14/Jul/2026:02:00:02 +0000] "GET /../../../etc/passwd '
        'HTTP/1.1" 404 5 "-" "Mozilla/5.0"',
        '198.51.100.7 - - [14/Jul/2026:02:00:03 +0000] "GET /.git/config HTTP/1.1" '
        '404 5 "-" "nikto/2.5"',
    ]
)


def _titles(findings):
    return " || ".join(f.title for f in findings)


def test_detects_successful_bruteforce_as_critical():
    fs = analyze_logs(_AUTH_BRUTE_SUCCESS, "auth.log")
    assert len(fs) == 1
    f = fs[0]
    assert f.severity.value == "critical"
    assert f.attack_technique == "T1110"
    assert "203.0.113.9" in f.title
    assert "203.0.113.9" in f.evidence  # cita as linhas reais (grounding)


def test_detects_bruteforce_without_success_as_medium():
    fs = analyze_logs(_AUTH_BRUTE_ONLY, "auth.log")
    assert len(fs) == 1
    assert fs[0].severity.value == "medium"
    assert fs[0].attack_technique == "T1110"


def test_bruteforce_below_threshold_is_ignored():
    text = "\n".join(
        f"sshd[{i}]: Failed password for root from 10.0.0.1 port 5{i} ssh2" for i in range(3)
    )
    assert analyze_logs(text, "auth.log") == []


def test_detects_web_attacks_and_scanner():
    fs = analyze_logs(_ACCESS, "access.log")
    titles = _titles(fs)
    assert "SQL Injection" in titles  # union+select (URL-encoded) normalizado
    assert "Path Traversal" in titles
    assert "arquivo sensível" in titles  # /.git/config
    assert "ferramenta de scan" in titles  # sqlmap/nikto UA
    for f in fs:
        assert f.attack_technique in ("T1190", "T1595")


def test_empty_and_noise_produce_nothing():
    assert analyze_logs("", "x") == []
    assert analyze_logs("linha qualquer sem padrão\noutra linha\n", "x") == []


def test_runner_available_and_scans_file(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(_AUTH_BRUTE_ONLY)
    r = LogAnalysisRunner()
    assert r.available() is True
    fs = r.scan(str(log))
    assert len(fs) == 1 and fs[0].attack_technique == "T1110"


def test_runner_scans_directory(tmp_path):
    (tmp_path / "auth.log").write_text(_AUTH_BRUTE_SUCCESS)
    (tmp_path / "access.log").write_text(_ACCESS)
    fs = LogAnalysisRunner().scan(str(tmp_path))
    assert len(fs) >= 4
    assert fs[0].severity.value == "critical"  # ordenado por severidade


def test_runner_missing_path_raises():
    import pytest

    with pytest.raises(FileNotFoundError):
        LogAnalysisRunner().scan("/caminho/que/nao/existe.log")
