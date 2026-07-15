"""Testes do parser do katana — saída de URLs (uma por linha)."""

from eigan.engine.base import ToolResult
from plugins.red.katana.parser import parse
from plugins.red.katana.runner import KatanaRunner

_URLS = "\n".join(
    [
        "https://demo.testfire.net/",
        "https://demo.testfire.net/login.jsp",
        "https://demo.testfire.net/search.jsp?query=abc",
        "https://demo.testfire.net/bank/transaction.jsp?id=1",
        "https://demo.testfire.net/",  # duplicada → dedup
        "lixo-sem-esquema",  # ignorada
    ]
)


def test_counts_urls_and_params():
    findings = parse(ToolResult(0, _URLS, ""), "https://demo.testfire.net/")
    assert len(findings) == 1
    f = findings[0]
    assert f.source_tool == "katana"
    assert f.affected_asset == "demo.testfire.net"
    # 4 URLs únicas (dedup + descarta 'lixo'), 2 com parâmetros
    assert "4 URL(s), 2 com parâmetros" in f.title
    assert "search.jsp?query=abc" in f.evidence
    assert f.attack_technique.startswith("T1595")


def test_empty_output_yields_nothing():
    assert parse(ToolResult(0, "", ""), "x") == []


def test_build_args_are_token_list():
    args = KatanaRunner().build_args("https://x/", depth=2)
    assert all(isinstance(a, str) and " " not in a for a in args)
    assert "-depth" in args and args[args.index("-u") + 1] == "https://x/"
