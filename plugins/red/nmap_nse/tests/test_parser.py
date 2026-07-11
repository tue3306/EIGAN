"""Teste do parser do nmap-nse (elementos <script> do XML → findings)."""

from eigan.engine.base import ToolResult
from eigan.findings.schema import Severity

from plugins.red.nmap_nse.parser import parse

# XML nativo do nmap com resultados NSE (formato documentado do -oX).
_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
        <script id="smb-vuln-ms17-010" output="State: VULNERABLE&#10;IDs: CVE-2017-0143"/>
      </port>
      <port protocol="tcp" portid="139">
        <state state="open"/>
        <script id="smb-os-discovery" output="OS: Windows 6.1"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_nse_parses_vulnerable_script_as_high():
    findings = parse(ToolResult(0, _XML, ""), "10.0.0.5")
    vuln = [f for f in findings if "ms17-010" in f.title]
    assert vuln, "script VULNERABLE deve virar finding"
    f = vuln[0]
    assert f.severity is Severity.HIGH  # VULNERABLE → alta (heurística de exposição)
    assert f.affected_asset == "10.0.0.5:445"
    # CVE citado entra como REFERÊNCIA + UNVERIFIED (não afirmamos CVSS — §3.1).
    assert any("CVE-2017-0143" in r for r in f.references)
    assert "UNVERIFIED" in f.description


def test_nse_non_vuln_script_is_info():
    findings = parse(ToolResult(0, _XML, ""), "10.0.0.5")
    info = [f for f in findings if "os-discovery" in f.title]
    assert info and info[0].severity is Severity.INFO


def test_nse_empty_or_bad_xml_is_no_findings():
    assert parse(ToolResult(0, "", ""), "x") == []
    assert parse(ToolResult(0, "<broken", ""), "x") == []
