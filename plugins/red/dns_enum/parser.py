"""Parser do dns-enum (dig): registros DNS + detecção de zone transfer (AXFR).

O runner agrega várias consultas dig numa só saída, cada bloco prefixado por
``;; EIGAN-SECTION <label>`` (``RECORD:<tipo>`` ou ``AXFR:<nameserver>``). Um bloco
AXFR **com registros** significa que a transferência de zona foi PERMITIDA — expõe
a zona inteira (CWE-200). Nada é inventado: só o que o dig realmente retornou (§2).
"""

from __future__ import annotations

from eigan.engine.base import ToolResult
from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "dns-enum"
_SECTION = ";; EIGAN-SECTION "


def _answer_lines(text: str) -> list[str]:
    """Linhas de resposta do dig (`+answer`): descarta comentários/linhas vazias."""
    out: list[str] = []
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith(";"):
            continue
        out.append(ln)
    return out


def _rdata(line: str) -> str:
    """RDATA de um registro dig (5º campo em diante: NAME TTL CLASS TYPE RDATA)."""
    parts = line.split(None, 4)
    return parts[4] if len(parts) >= 5 else line


def nameservers_from_dig(text: str) -> list[str]:
    """Hostnames dos registros NS (rdata), sem o ponto final — para tentar AXFR."""
    ns: list[str] = []
    for ln in _answer_lines(text):
        parts = ln.split(None, 4)
        if len(parts) >= 5 and parts[3].upper() == "NS":
            host = parts[4].strip().rstrip(".")
            if host and host not in ns:
                ns.append(host)
    return ns


def _sections(stdout: str) -> list[tuple[str, str]]:
    """Divide a saída combinada do runner em pares (label, corpo)."""
    sections: list[tuple[str, str]] = []
    label = ""
    body: list[str] = []
    for line in stdout.splitlines():
        if line.startswith(_SECTION):
            if label:
                sections.append((label, "\n".join(body)))
            label = line[len(_SECTION) :].strip()
            body = []
        else:
            body.append(line)
    if label:
        sections.append((label, "\n".join(body)))
    return sections


def parse(result: ToolResult, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for label, body in _sections(result.stdout):
        lines = _answer_lines(body)
        if not lines:
            continue  # AXFR recusado / registro ausente → nenhum finding (sem inventar)
        if label.startswith("AXFR:"):
            ns = label[len("AXFR:") :]
            hosts = sorted({ln.split(None, 1)[0].rstrip(".") for ln in lines if ln.split()})
            findings.append(
                Finding(
                    title=f"Zone transfer (AXFR) permitido em {ns}",
                    # AXFR aberto expõe TODO o mapa de DNS/rede — recon completa da
                    # superfície para um atacante. Severidade alta (crítica) justificada.
                    severity=Severity.CRITICAL,
                    affected_asset=target,
                    source_tool=TOOL,
                    cwe="CWE-200",  # Exposure of Sensitive Information
                    owasp="A05:2021",  # Security Misconfiguration
                    attack_technique="T1590.002",  # Gather Victim Network Info: DNS
                    description=(
                        f"O nameserver {ns} respondeu a um zone transfer (AXFR) de "
                        f"{target}, expondo {len(lines)} registro(s) da zona "
                        f"({len(hosts)} host(s) distintos). Revela todo o mapa de "
                        "DNS/rede — restrinja AXFR a servidores autorizados."
                    ),
                    evidence="\n".join(lines[:40])[:1500],
                    reproduction=f"dig +noall +answer axfr @{ns} {target}",
                    confidence=Confidence.CONFIRMED,  # a transferência ocorreu de fato
                    references=[
                        "https://cwe.mitre.org/data/definitions/200.html",
                        "https://attack.mitre.org/techniques/T1590/002/",
                    ],
                )
            )
        elif label.startswith("RECORD:"):
            rtype = label[len("RECORD:") :]
            values = [_rdata(ln) for ln in lines]
            findings.append(
                Finding(
                    title=f"Registros DNS {rtype} de {target}",
                    severity=Severity.INFO,
                    affected_asset=target,
                    source_tool=TOOL,
                    attack_technique="T1590.002",
                    description=f"{len(values)} registro(s) {rtype}: " + "; ".join(values[:12]),
                    evidence="\n".join(lines[:20])[:800],
                    confidence=Confidence.FIRM,
                    references=["https://attack.mitre.org/techniques/T1590/002/"],
                )
            )
    return findings
