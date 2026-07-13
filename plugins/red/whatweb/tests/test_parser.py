"""Testes do parser do whatweb — fixture da saída JSON real (demo.testfire.net)."""

from plugins.red.whatweb.parser import parse
from plugins.red.whatweb.runner import WhatWebRunner

from eigan.engine.base import ToolResult

_JSON = (
    '[\n{"target":"https://demo.testfire.net/","http_status":200,'
    '"plugins":{"Apache":{},"Cookies":{"string":["JSESSIONID"]},'
    '"HTTPServer":{"string":["Apache-Coyote/1.1"]},"Java":{},'
    '"Title":{"string":["Altoro Mutual"]}}}\n]'
)


def test_parses_technologies():
    findings = parse(ToolResult(0, _JSON, ""), "https://demo.testfire.net/")
    assert len(findings) == 1
    f = findings[0]
    assert f.source_tool == "whatweb"
    assert f.affected_asset == "https://demo.testfire.net/"
    # tecnologias no título (Apache/Java); ruído (Title/Cookies) fora dele
    assert "Apache" in f.title and "Java" in f.title
    assert "Altoro Mutual" not in f.title
    assert f.attack_technique == "T1592.002"


def test_empty_output_yields_nothing():
    assert parse(ToolResult(0, "", ""), "x") == []
    assert parse(ToolResult(0, "não-json", ""), "x") == []


def test_build_args_are_token_list():
    args = WhatWebRunner().build_args("https://x/", aggression=3)
    assert all(isinstance(a, str) and " " not in a for a in args if a != "https://x/")
    assert "--log-json=-" in args and args[-1] == "https://x/"
