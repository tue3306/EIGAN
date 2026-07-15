"""Testes do parser do amass — subdomínios um por linha, com filtro de ruído."""

from eigan.engine.base import ToolResult
from plugins.red.amass.parser import parse
from plugins.red.amass.runner import AmassRunner, _domain

_OUT = "\n".join(
    [
        "www.testfire.net",
        "demo.testfire.net",
        "demo.testfire.net",  # duplicado → dedup
        "linha de log com espaco",  # ruído (espaço)
        "semponto",  # ruído (sem ponto)
        "api.testfire.net",
    ]
)


def test_parses_subdomains_dedup_and_filters_noise():
    findings = parse(ToolResult(0, _OUT, ""), "testfire.net")
    assets = {f.affected_asset for f in findings}
    assert assets == {"www.testfire.net", "demo.testfire.net", "api.testfire.net"}
    assert all(f.source_tool == "amass" for f in findings)
    assert all(f.attack_technique.startswith("T1590") for f in findings)


def test_empty_yields_nothing():
    assert parse(ToolResult(0, "", ""), "x") == []


def test_domain_extraction():
    assert _domain("https://demo.testfire.net:443/path") == "demo.testfire.net"
    assert _domain("testfire.net") == "testfire.net"
    assert _domain("10.0.0.5:8080") == "10.0.0.5"


def test_build_args_passive_with_domain():
    args = AmassRunner().build_args("https://demo.testfire.net/")
    assert args[0] == "enum" and "-passive" in args
    assert "-d" in args and args[args.index("-d") + 1] == "demo.testfire.net"
