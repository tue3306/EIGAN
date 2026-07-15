"""Testes do parser do nuclei (saída de amostra, sem executar a ferramenta)."""

from plugins.red.nuclei.parser import parse
from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Severity


def test_nuclei_parse_jsonl():
    line = (
        '{"template-id":"CVE-test","matched-at":"http://h/","info":'
        '{"name":"Test","severity":"high","classification":'
        '{"cvss-score":8.8,"cvss-metrics":"CVSS:3.1/AV:N","cwe-id":["cwe-89"],'
        '"cve-id":["CVE-2024-0001"]}}}'
    )
    findings = parse(ToolResult(0, line, ""), "http://h/")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.cvss.version == "3.1"
    assert f.cwe == "CWE-89"
    # CVE do template não confirmado contra NVD => UNVERIFIED
    assert f.confidence == Confidence.UNVERIFIED
    assert any("CVE-2024-0001" in r for r in f.references)


def test_nuclei_parse_ignores_garbage_lines():
    assert parse(ToolResult(0, "not json\n\n", ""), "x") == []


def test_nuclei_parse_survives_out_of_range_cvss():
    """Regressão: cvss-score fora de [0,10] (template custom/quebrado) NÃO pode
    derrubar o parse inteiro — a finding é preservada, só sem o CVSS inválido (§2:
    não fabricar/clampar um score, e §24: não perder achados válidos por 1 ruim)."""
    bad = (
        '{"template-id":"custom","matched-at":"http://h/x","info":'
        '{"name":"X","severity":"high","classification":'
        '{"cvss-score":11.0,"cvss-metrics":"CVSS:3.1/AV:N"}}}'
    )
    good = (
        '{"template-id":"ok","matched-at":"http://h/y","info":'
        '{"name":"Y","severity":"low","classification":{"cvss-score":5.0}}}'
    )
    findings = parse(ToolResult(0, bad + "\n" + good, ""), "http://h/")
    assert len(findings) == 2  # nenhuma finding válida é perdida
    assert findings[0].cvss is None  # score inválido descartado, não fabricado
    assert findings[1].cvss is not None and findings[1].cvss.score == 5.0


def test_nuclei_parse_survives_malformed_cwe():
    """Regressão: cwe-id malformado (sem prefixo 'CWE-', ou inteiro) num template
    custom/quebrado NÃO pode derrubar o parse inteiro — mesma classe do bug do
    cvss (§24). O schema Finding valida o formato 'CWE-<n>' e levantaria ValueError;
    o parser tem de normalizar (número claro → CWE-N) ou descartar (irreconhecível
    → None, sem fabricar §2), nunca crashar."""
    no_prefix = (
        '{"template-id":"a","matched-at":"http://h/a","info":'
        '{"name":"A","severity":"medium","classification":{"cwe-id":["79"]}}}'
    )
    as_int = (
        '{"template-id":"b","matched-at":"http://h/b","info":'
        '{"name":"B","severity":"low","classification":{"cwe-id":[89]}}}'
    )
    garbage = (
        '{"template-id":"c","matched-at":"http://h/c","info":'
        '{"name":"C","severity":"info","classification":{"cwe-id":["not-a-cwe"]}}}'
    )
    findings = parse(ToolResult(0, "\n".join([no_prefix, as_int, garbage]), ""), "http://h/")
    assert len(findings) == 3  # nenhuma finding perdida por causa de um cwe ruim
    assert findings[0].cwe == "CWE-79"  # "79" normalizado para o formato do schema
    assert findings[1].cwe == "CWE-89"  # 89 (inteiro) normalizado
    assert findings[2].cwe is None  # irreconhecível: descartado, não fabricado
