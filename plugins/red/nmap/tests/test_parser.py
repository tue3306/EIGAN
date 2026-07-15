"""Testes do parser e do runner do nmap (segurança de args + parse do XML)."""

from eigan.engine.base import ToolResult
from eigan.findings.schema import Severity
from plugins.red.nmap.parser import parse
from plugins.red.nmap.runner import NmapRunner

_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <address addr="127.0.0.1" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="80">
    <state state="open"/>
    <service name="http" product="nginx" version="1.25.3"/>
   </port>
   <port protocol="tcp" portid="81">
    <state state="closed"/>
   </port>
  </ports>
 </host>
</nmaprun>"""


def test_nmap_build_args_are_token_list():
    args = NmapRunner().build_args("127.0.0.1", ports="80,443")
    assert "-oX" in args and "-" in args
    assert args[-1] == "127.0.0.1"
    assert all(isinstance(a, str) for a in args)


def test_nmap_parse_open_ports_only():
    findings = parse(ToolResult(0, _NMAP_XML, ""), "127.0.0.1")
    assert len(findings) == 1
    f = findings[0]
    assert f.affected_asset == "127.0.0.1:80"
    assert f.severity == Severity.INFO
    assert f.attack_technique == "T1046"


def test_nmap_parse_empty():
    assert parse(ToolResult(0, "", ""), "x") == []
