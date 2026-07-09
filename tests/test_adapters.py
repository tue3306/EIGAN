"""Testes dos parsers de adapter (com saída de amostra, sem executar ferramentas).

Segurança: verifica que build_args nunca produz shell e usa tokens isolados.
"""

from vulnforge.engine.adapters.nmap_adapter import NmapAdapter
from vulnforge.engine.adapters.nuclei_adapter import NucleiAdapter
from vulnforge.engine.base import ToolResult
from vulnforge.findings.schema import Confidence, Severity

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
    args = NmapAdapter().build_args("127.0.0.1", ports="80,443")
    assert "-oX" in args and "-" in args
    assert args[-1] == "127.0.0.1"
    assert all(isinstance(a, str) for a in args)


def test_nmap_parse_open_ports_only():
    findings = NmapAdapter().parse(ToolResult(0, _NMAP_XML, ""), "127.0.0.1")
    assert len(findings) == 1
    f = findings[0]
    assert f.affected_asset == "127.0.0.1:80"
    assert f.severity == Severity.INFO
    assert f.attack_technique == "T1046"


def test_nmap_parse_empty():
    assert NmapAdapter().parse(ToolResult(0, "", ""), "x") == []


def test_nuclei_parse_jsonl():
    line = (
        '{"template-id":"CVE-test","matched-at":"http://h/","info":'
        '{"name":"Test","severity":"high","classification":'
        '{"cvss-score":8.8,"cvss-metrics":"CVSS:3.1/AV:N","cwe-id":["cwe-89"],'
        '"cve-id":["CVE-2024-0001"]}}}'
    )
    findings = NucleiAdapter().parse(ToolResult(0, line, ""), "http://h/")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.cvss.version == "3.1"
    assert f.cwe == "CWE-89"
    # CVE do template não confirmado contra NVD => UNVERIFIED
    assert f.confidence == Confidence.UNVERIFIED
    assert any("CVE-2024-0001" in r for r in f.references)


def test_nuclei_parse_ignores_garbage_lines():
    assert NucleiAdapter().parse(ToolResult(0, "not json\n\n", ""), "x") == []
