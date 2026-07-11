"""Teste do parser do enum4linux (usuários, shares, null session, domínio)."""

from eigan.engine.base import ToolResult
from eigan.findings.schema import Severity

from plugins.red.enum4linux.parser import parse

# Fixture no formato documentado do enum4linux (marcadores reais, sem inventar).
_OUT = """
 =========================================( Target Information )=========================================
Target ........... 10.0.0.5
 [+] Server 10.0.0.5 allows sessions using username '', password ''
 [+] Got domain/workgroup name: WORKGROUP
Domain Name: WORKGROUP
user:[administrator] rid:[0x1f4]
user:[guest] rid:[0x1f5]
user:[jsmith] rid:[0x3e8]
//10.0.0.5/IPC$\tMapping: OK\tListing: DENIED
//10.0.0.5/public\tMapping: OK\tListing: OK
//10.0.0.5/C$\tMapping: DENIED\tListing: N/A
"""


def test_enum4linux_parses_smb_facts():
    findings = parse(ToolResult(0, _OUT, ""), "10.0.0.5")
    titles = " | ".join(f.title for f in findings)
    # null session detectada (misconfig) — severidade média, sem afirmar CVE.
    null = [f for f in findings if "null session" in f.title.lower()]
    assert null and null[0].severity is Severity.MEDIUM and null[0].cwe == "CWE-287"
    # usuários agregados (3), com técnica ATT&CK de Account Discovery.
    users = [f for f in findings if "usuário" in f.title.lower()]
    assert users and "3 usuário" in users[0].title and users[0].attack_technique == "T1087"
    # apenas shares mapeáveis (Mapping: OK) viram finding; C$ (DENIED) não.
    shares = {f.affected_asset for f in findings if "Share SMB" in f.title}
    assert shares == {"10.0.0.5/IPC$", "10.0.0.5/public"}
    assert "WORKGROUP" in titles


def test_enum4linux_empty_output_is_no_findings():
    assert parse(ToolResult(0, "", ""), "10.0.0.5") == []
