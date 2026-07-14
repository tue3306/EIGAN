"""Exposure prober (Red) — detecta arquivos/segredos VAZADOS na app web.

"Dados vazados": arquivos sensíveis servidos por engano (``.git``, ``.env``,
backups, ``.aws/credentials``, chaves privadas, ``server-status``/``phpinfo``) e
segredos embutidos em respostas (chaves AWS/Google/Slack, private keys, tokens).

Grounding (§3.1): NADA é inventado. Um caminho só vira finding se retornar 200 E
casar a **assinatura de conteúdo** esperada (evita soft-404). Segredos só entram
se o padrão casar na resposta real — e são **mascarados** na evidência (não
gravamos o segredo inteiro; §5 redaction). Cada finding tem CWE + técnica ATT&CK.
"""

from __future__ import annotations

import re

from eigan.findings.schema import Confidence, Finding, Severity

TOOL = "exposure"

# (path, assinatura de conteúdo, rótulo, severidade, CWE, técnica ATT&CK)
# A assinatura confirma que é o arquivo real (não um 404 genérico que devolve 200).
_PATHS: list[tuple[str, re.Pattern[str], str, Severity, str, str]] = [
    (
        "/.git/config",
        re.compile(r"\[core\]|\[remote|repositoryformatversion"),
        "Repositório Git exposto (.git/config)",
        Severity.HIGH,
        "CWE-527",
        "T1592",
    ),
    (
        "/.git/HEAD",
        re.compile(r"ref:\s*refs/"),
        "Repositório Git exposto (.git/HEAD)",
        Severity.HIGH,
        "CWE-527",
        "T1592",
    ),
    (
        "/.env",
        re.compile(r"(?im)^[A-Z0-9_]+\s*="),
        "Arquivo .env exposto (segredos de ambiente)",
        Severity.CRITICAL,
        "CWE-522",
        "T1552",
    ),
    (
        "/.aws/credentials",
        re.compile(r"aws_access_key_id|\[default\]"),
        "Credenciais AWS expostas (.aws/credentials)",
        Severity.CRITICAL,
        "CWE-522",
        "T1552",
    ),
    (
        "/.svn/entries",
        re.compile(r"dir|svn:|\d+"),
        "Repositório SVN exposto (.svn/entries)",
        Severity.HIGH,
        "CWE-527",
        "T1592",
    ),
    (
        "/.htpasswd",
        re.compile(r"[^:\s]+:\$?(?:apr1|2y|1)?\$?"),
        "Arquivo .htpasswd exposto (hashes de senha)",
        Severity.HIGH,
        "CWE-522",
        "T1552",
    ),
    (
        "/config.php.bak",
        re.compile(r"<\?php|define\(|\$"),
        "Backup de configuração exposto (config.php.bak)",
        Severity.HIGH,
        "CWE-530",
        "T1592",
    ),
    (
        "/wp-config.php.bak",
        re.compile(r"DB_PASSWORD|DB_NAME|<\?php"),
        "Backup do wp-config exposto (wp-config.php.bak)",
        Severity.CRITICAL,
        "CWE-522",
        "T1552",
    ),
    (
        "/backup.sql",
        re.compile(r"(?i)INSERT INTO|CREATE TABLE|DROP TABLE"),
        "Dump de banco exposto (backup.sql)",
        Severity.CRITICAL,
        "CWE-530",
        "T1592",
    ),
    (
        "/dump.sql",
        re.compile(r"(?i)INSERT INTO|CREATE TABLE|DROP TABLE"),
        "Dump de banco exposto (dump.sql)",
        Severity.CRITICAL,
        "CWE-530",
        "T1592",
    ),
    (
        "/.DS_Store",
        re.compile(r"Bud1|\x00\x00\x00\x01Bud1", re.DOTALL),
        "Arquivo .DS_Store exposto (estrutura de diretórios)",
        Severity.LOW,
        "CWE-200",
        "T1592",
    ),
    (
        "/server-status",
        re.compile(r"Apache Server Status|Server uptime"),
        "Apache server-status exposto (info do servidor)",
        Severity.MEDIUM,
        "CWE-200",
        "T1592",
    ),
    (
        "/phpinfo.php",
        re.compile(r"phpinfo\(\)|PHP Version"),
        "phpinfo() exposto (info de ambiente PHP)",
        Severity.MEDIUM,
        "CWE-200",
        "T1592",
    ),
    (
        "/.ssh/id_rsa",
        re.compile(r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----"),
        "Chave SSH privada exposta (.ssh/id_rsa)",
        Severity.CRITICAL,
        "CWE-522",
        "T1552",
    ),
]

# Segredos embutidos em respostas (chaves reais em texto). Grounded: só o que casa.
_SECRETS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "Google API Key"),
    (re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"), "Slack Token"),
    (re.compile(r"ghp_[0-9A-Za-z]{36}"), "GitHub Personal Access Token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "Private Key"),
    (
        re.compile(
            r"(?i)(?:api[_-]?key|secret|passwd|password|token)\s*[=:]\s*"
            r"['\"][A-Za-z0-9_\-]{16,}['\"]"
        ),
        "Credencial embutida",
    ),
]


def _mask(secret: str) -> str:
    """Mascara o miolo de um segredo (não gravamos o valor inteiro — §5)."""
    s = secret.strip()
    if len(s) <= 10:
        return s[:2] + "***"
    return f"{s[:6]}…{s[-4:]} ({len(s)} chars)"


def classify(path: str, url: str, status: int, body: str) -> Finding | None:
    """Se ``path`` casa uma exposição conhecida (200 + assinatura), devolve o
    finding; senão ``None`` (não afirma exposição sem evidência)."""
    if status != 200 or not body:
        return None
    for p, sig, label, sev, cwe, tech in _PATHS:
        if p == path and sig.search(body):
            return Finding(
                title=label,
                severity=sev,
                affected_asset=url,
                source_tool=TOOL,
                cwe=cwe,
                attack_technique=tech,
                owasp="A05:2021",  # Security Misconfiguration
                description=(
                    f"O recurso {path} está acessível publicamente e retornou conteúdo "
                    f"sensível confirmado. Exposição de dados/segredos (OWASP A05, {cwe})."
                ),
                evidence=f"GET {url} → 200\n{body[:400].strip()}",
                reproduction=f"curl -sk {url}",
                confidence=Confidence.CONFIRMED,
                references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
            )
    return None


def scan_secrets(url: str, body: str) -> list[Finding]:
    """Segredos embutidos na resposta (chaves/tokens/creds), mascarados."""
    out: list[Finding] = []
    seen: set[str] = set()
    for rx, label in _SECRETS:
        for m in rx.finditer(body or ""):
            token = m.group(0)
            if token in seen:
                continue
            seen.add(token)
            out.append(
                Finding(
                    title=f"Segredo vazado na resposta: {label}",
                    severity=Severity.CRITICAL
                    if "Key" in label or "Token" in label
                    else Severity.HIGH,
                    affected_asset=url,
                    source_tool=TOOL,
                    cwe="CWE-798",  # Use of Hard-coded Credentials / secret exposto
                    attack_technique="T1552",
                    owasp="A05:2021",
                    description=f"{label} exposto no corpo da resposta de {url}.",
                    evidence=f"{label}: {_mask(token)}",  # mascarado (§5)
                    confidence=Confidence.FIRM,
                    references=["https://cwe.mitre.org/data/definitions/798.html"],
                )
            )
    return out


def sensitive_paths() -> list[str]:
    """Lista de caminhos sensíveis a sondar (usada pelo runner)."""
    return [p for p, *_ in _PATHS]
