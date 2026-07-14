"""Detectores de log-analysis (Blue) — padrões reais sobre conteúdo real.

Grounding (§3.1): NADA é inventado. Cada finding cita as linhas reais que o
dispararam (evidência) e só afirma o que os padrões casaram. Cada detecção é
mapeada a uma técnica MITRE ATT&CK (campo ``attack_technique``) — a base da
correlação Purple (ataque×detecção). Sem dependência externa: parsing puro em
Python (analisar log é passivo).

Formatos cobertos (os mais comuns em avaliações Web+Infra):
* SSH/PAM (``auth.log``/``secure``): força-bruta e login pós-falhas.
* Acesso web (CLF/Combined — nginx/apache): assinaturas de ataque na requisição,
  user-agents de scanner e varredura (muitos 4xx de um mesmo IP).
* ``sudo``: falhas de autenticação / tentativas de escalonamento.
"""

from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import unquote_plus

from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "log-analysis"

# Limiares (heurísticas NOSSAS, não fatos externos — §5): ajustáveis por opção.
_BRUTE_MIN = 5  # tentativas falhas do MESMO IP para sinalizar força-bruta
_SCAN_MIN = 20  # respostas 4xx do MESMO IP para sinalizar varredura

# ── SSH / PAM ────────────────────────────────────────────────────────────────
_SSH_FAIL = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
_SSH_OK = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
_SUDO_FAIL = re.compile(r"sudo:.*authentication failure.*(?:user=(?P<user>\S+)|logname=(?P<l>\S+))")

# ── Acesso web (CLF/Combined) ────────────────────────────────────────────────
_ACCESS = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[[^\]]+\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})'
    r'(?:\s+\S+\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)

# Assinaturas de ataque na requisição → (rótulo, técnica ATT&CK, CWE, severidade).
_WEB_SIGS: list[tuple[re.Pattern[str], str, str, str | None, Severity]] = [
    (
        re.compile(r"(?i)\bunion\s+select\b|\bor\s+1=1\b|sleep\(\d|information_schema"),
        "Tentativa de SQL Injection",
        "T1190",
        "CWE-89",
        Severity.HIGH,
    ),
    (
        re.compile(r"(?i)<script|%3cscript|onerror=|javascript:"),
        "Tentativa de XSS",
        "T1190",
        "CWE-79",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"(?:\.\./){2,}|%2e%2e%2f|/etc/passwd|boot\.ini|win\.ini"),
        "Tentativa de Path Traversal / LFI",
        "T1190",
        "CWE-22",
        Severity.HIGH,
    ),
    (
        re.compile(r"(?i);\s*(?:cat|wget|curl|nc|bash|sh)\s|%3b|\|\s*(?:id|whoami)\b|\$\(.*\)"),
        "Tentativa de Command Injection",
        "T1190",
        "CWE-78",
        Severity.HIGH,
    ),
    (
        re.compile(r"(?i)/\.git/|/\.env\b|/wp-config\.php|/\.aws/|/phpinfo"),
        "Sondagem de arquivo sensível exposto",
        "T1595",
        "CWE-538",
        Severity.MEDIUM,
    ),
]
# User-agents de ferramentas de scan/ataque (indicador de reconhecimento ativo).
_SCANNER_UA = re.compile(
    r"(?i)\b(sqlmap|nikto|nmap|masscan|acunetix|nuclei|dirbuster|gobuster|"
    r"wpscan|fimap|hydra|zgrab|nessus|openvas)\b"
)


def _finding(
    title: str,
    severity: Severity,
    asset: str,
    *,
    technique: str,
    description: str,
    evidence: str,
    cwe: str | None = None,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        affected_asset=asset,
        source_tool=TOOL,
        attack_technique=technique,
        cwe=cwe,
        description=description,
        evidence=evidence[:1500],
        confidence=Confidence.FIRM,
    )


def _ssh_findings(lines: list[str], source: str) -> list[Finding]:
    fails: dict[str, list[str]] = defaultdict(list)
    fail_users: dict[str, set[str]] = defaultdict(set)
    ok_by_ip: dict[str, set[str]] = defaultdict(set)
    ok_lines: dict[str, str] = {}
    for ln in lines:
        m = _SSH_FAIL.search(ln)
        if m:
            ip = m.group("ip")
            fails[ip].append(ln.strip())
            fail_users[ip].add(m.group("user"))
            continue
        m = _SSH_OK.search(ln)
        if m:
            ip = m.group("ip")
            ok_by_ip[ip].add(m.group("user"))
            ok_lines.setdefault(ip, ln.strip())
    out: list[Finding] = []
    for ip, attempts in sorted(fails.items(), key=lambda kv: len(kv[1]), reverse=True):
        n = len(attempts)
        if n < _BRUTE_MIN:
            continue
        succeeded = ip in ok_by_ip
        users = ", ".join(sorted(fail_users[ip])[:5])
        if succeeded:
            out.append(
                _finding(
                    f"Possível força-bruta SSH BEM-SUCEDIDA de {ip}",
                    Severity.CRITICAL,
                    source,
                    technique="T1110",
                    description=(
                        f"{n} tentativas falhas de senha SSH do IP {ip} (usuários: {users}) "
                        f"SEGUIDAS de login aceito para {', '.join(sorted(ok_by_ip[ip]))}. "
                        "Indício forte de comprometimento por força-bruta (ATT&CK T1110 → "
                        "T1078 Valid Accounts)."
                    ),
                    evidence="\n".join(attempts[:8] + [ok_lines.get(ip, "")]).strip(),
                )
            )
        else:
            out.append(
                _finding(
                    f"Força-bruta SSH de {ip} ({n} falhas)",
                    Severity.MEDIUM,
                    source,
                    technique="T1110",
                    description=(
                        f"{n} tentativas falhas de senha SSH do IP {ip} (usuários: {users}). "
                        "Padrão de força-bruta / password spraying (ATT&CK T1110)."
                    ),
                    evidence="\n".join(attempts[:8]),
                )
            )
    return out


def _sudo_findings(lines: list[str], source: str) -> list[Finding]:
    hits = [ln.strip() for ln in lines if _SUDO_FAIL.search(ln)]
    if len(hits) < 3:
        return []
    return [
        _finding(
            f"Falhas repetidas de autenticação sudo ({len(hits)})",
            Severity.MEDIUM,
            source,
            technique="T1548",
            description=(
                f"{len(hits)} falhas de autenticação em sudo — possível tentativa de "
                "escalonamento de privilégio ou abuso de conta (ATT&CK T1548.003)."
            ),
            evidence="\n".join(hits[:8]),
        )
    ]


def _web_findings(lines: list[str], source: str) -> list[Finding]:
    out: list[Finding] = []
    by_sig: dict[str, list[str]] = defaultdict(list)
    sig_meta: dict[str, tuple[str, str | None, Severity]] = {}
    scanner_hits: list[str] = []
    status4xx: dict[str, int] = defaultdict(int)
    matched_any = False
    for ln in lines:
        m = _ACCESS.match(ln.strip())
        if not m:
            continue
        matched_any = True
        ip, path, status = m.group("ip"), m.group("path"), m.group("status")
        ua = m.group("ua") or ""
        if status.startswith("4"):
            status4xx[ip] += 1
        # normaliza a URL (decodifica %XX e '+'→espaço) para casar assinaturas
        # ofuscadas por URL-encoding (ex.: union+select, %2e%2e%2f).
        decoded = unquote_plus(path)
        for rx, label, tech, cwe, sev in _WEB_SIGS:
            if rx.search(path) or rx.search(decoded):
                by_sig[label].append(ln.strip())
                sig_meta[label] = (tech, cwe, sev)
        if _SCANNER_UA.search(ua):
            scanner_hits.append(ln.strip())
    if not matched_any:
        return out
    for label, samples in by_sig.items():
        tech, cwe, sev = sig_meta[label]
        out.append(
            _finding(
                f"{label} em logs de acesso ({len(samples)}×)",
                sev,
                source,
                technique=tech,
                cwe=cwe,
                description=(
                    f"{len(samples)} requisição(ões) com assinatura de «{label.lower()}» "
                    "nos logs de acesso web. Indica ataque à aplicação exposta "
                    f"(ATT&CK {tech})."
                ),
                evidence="\n".join(samples[:6]),
            )
        )
    if scanner_hits:
        out.append(
            _finding(
                f"Uso de ferramenta de scan detectado ({len(scanner_hits)}×)",
                Severity.LOW,
                source,
                technique="T1595",
                description=(
                    f"{len(scanner_hits)} requisição(ões) com user-agent de ferramenta de "
                    "varredura/ataque (sqlmap/nikto/nmap/…). Reconhecimento ativo (ATT&CK T1595)."
                ),
                evidence="\n".join(scanner_hits[:6]),
            )
        )
    for ip, n in sorted(status4xx.items(), key=lambda kv: kv[1], reverse=True):
        if n < _SCAN_MIN:
            continue
        out.append(
            _finding(
                f"Varredura de conteúdo de {ip} ({n} respostas 4xx)",
                Severity.LOW,
                source,
                technique="T1595",
                description=(
                    f"O IP {ip} gerou {n} respostas 4xx — padrão de enumeração de "
                    "diretórios/arquivos (ATT&CK T1595.003)."
                ),
                evidence=f"{ip}: {n} respostas 4xx nos logs de acesso.",
            )
        )
    return out


def analyze_logs(text: str, source: str) -> list[Finding]:
    """Roda todos os detectores sobre o conteúdo de log e devolve findings.

    ``source`` identifica a origem (nome do arquivo/host) — vai para o ativo
    afetado. Ordena por severidade (mais grave primeiro)."""
    lines = text.splitlines()
    findings = _ssh_findings(lines, source) + _sudo_findings(lines, source)
    findings += _web_findings(lines, source)
    findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return findings
