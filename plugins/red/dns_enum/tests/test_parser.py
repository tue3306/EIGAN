"""Testes do parser do dns-enum (saída real do dig, sem executar a ferramenta)."""

from plugins.red.dns_enum.parser import nameservers_from_dig, parse

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Severity

# Formato real do `dig +noall +answer` (verificado): NAME<TAB>TTL<TAB>IN<TAB>TYPE<TAB>RDATA.
_NS = "example.com.\t3600\tIN\tNS\tns1.example.com.\nexample.com.\t3600\tIN\tNS\tns2.example.com.\n"


def test_nameservers_from_dig():
    assert nameservers_from_dig(_NS) == ["ns1.example.com", "ns2.example.com"]


def test_nameservers_from_dig_empty():
    assert nameservers_from_dig("") == []


def test_axfr_success_is_critical_records_are_info():
    combined = (
        ";; EIGAN-SECTION RECORD:NS\n" + _NS + ";; EIGAN-SECTION RECORD:MX\n"
        "example.com.\t3600\tIN\tMX\t10 mail.example.com.\n"
        ";; EIGAN-SECTION AXFR:ns1.example.com\n"
        "example.com.\t3600\tIN\tSOA\tns1.example.com. admin.example.com. 1 900 900 1800 60\n"
        "example.com.\t3600\tIN\tNS\tns1.example.com.\n"
        "internal.example.com.\t3600\tIN\tA\t10.0.0.5\n"
        "vpn.example.com.\t3600\tIN\tA\t10.0.0.6\n"
        # ns2 recusou o transfer → seção vazia (comportamento seguro, sem finding):
        ";; EIGAN-SECTION AXFR:ns2.example.com\n"
    )
    findings = parse(ToolResult(0, combined, ""), "example.com")
    axfr = [f for f in findings if "AXFR" in f.title]
    assert len(axfr) == 1  # só ns1 permitiu; ns2 (vazio) não vira finding
    assert axfr[0].severity is Severity.CRITICAL
    assert axfr[0].confidence is Confidence.CONFIRMED
    assert axfr[0].cwe == "CWE-200"
    assert "internal.example.com" in axfr[0].evidence  # host vazado consta na evidência

    records = [f for f in findings if f.severity is Severity.INFO]
    assert any("NS" in f.title for f in records)
    assert any("MX" in f.title for f in records)


def test_no_records_yields_no_findings():
    combined = ";; EIGAN-SECTION RECORD:NS\n\n;; EIGAN-SECTION AXFR:ns.example.com\n\n"
    assert parse(ToolResult(0, combined, ""), "example.com") == []
