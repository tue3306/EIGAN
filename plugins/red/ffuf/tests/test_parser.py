"""Testes do parser do ffuf — JSON de resultados e NDJSON, severidade sensível."""

from plugins.red.ffuf.parser import parse
from plugins.red.ffuf.runner import FfufRunner

from eigan.engine.base import ToolResult
from eigan.findings.schema import Severity

# JSON único (formato -json com bloco "results")
_JSON = (
    '{"results":['
    '{"input":{"FUZZ":"admin"},"url":"https://x/admin","status":200,"length":1024},'
    '{"input":{"FUZZ":".git/config"},"url":"https://x/.git/config","status":200,"length":92},'
    '{"input":{"FUZZ":"missing"},"url":"https://x/missing","status":404,"length":0}'
    "]}"
)
# NDJSON (uma linha por achado)
_NDJSON = (
    '{"url":"https://x/backup.sql","status":200,"length":50}\n'
    '{"url":"https://x/login","status":302,"length":0}'
)


def test_parses_json_results_and_flags_sensitive():
    findings = parse(ToolResult(0, _JSON, ""), "https://x/")
    assets = {f.affected_asset for f in findings}
    assert "https://x/admin" in assets
    # .git/config acessível → severidade MEDIUM (exposição sensível)
    git = next(f for f in findings if ".git" in f.affected_asset)
    assert git.severity is Severity.MEDIUM
    admin = next(f for f in findings if f.affected_asset.endswith("/admin"))
    assert admin.severity is Severity.INFO
    assert all(f.source_tool == "ffuf" for f in findings)


def test_parses_ndjson():
    findings = parse(ToolResult(0, _NDJSON, ""), "https://x/")
    assert len(findings) == 2
    sql = next(f for f in findings if "backup.sql" in f.affected_asset)
    assert sql.severity is Severity.MEDIUM  # backup + .sql acessível


def test_empty_yields_nothing():
    assert parse(ToolResult(0, "", ""), "x") == []


def test_build_args_have_fuzz_and_wordlist():
    args = FfufRunner().build_args("https://x")
    assert "-u" in args and "https://x/FUZZ" in args
    assert "-w" in args and args[args.index("-w") + 1]  # wordlist resolvida
    assert "-json" in args
