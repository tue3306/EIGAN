"""Auto Remediation (Blue) — artefatos de correção revisáveis (Pilar 6 / ADR-0008).

Gera, a partir de um :class:`~eigan.findings.schema.Finding`, um **playbook
Ansible** de correção como **sugestão revisável** — nunca aplicado
automaticamente, nunca contra terceiros sem revisão/escopo. Seleção de template é
**determinística** (por porta/serviço/palavra-chave do finding); a IA não entra.

Escopo honesto (§3.6): apenas o formato **Ansible** é gerado hoje, e só para os
tipos de finding com template. Bash/PowerShell/Terraform e demais tipos ficam
como *scaffold* (``generate`` retorna ``None`` — o chamador reporta "sem template
ainda"), sem fingir cobertura que não existe.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from ..findings.schema import Finding

_PORT_RE = re.compile(r":(\d{1,5})(?:/\w+)?$")

# Portas de serviços que NÃO deveriam estar expostos à internet (firewall Blue).
_SENSITIVE_PORTS: dict[int, str] = {
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    445: "SMB",
    139: "NetBIOS/SMB",
    3389: "RDP",
    23: "Telnet",
    21: "FTP",
}

_SAFETY_HEADER = (
    "# SUGESTÃO de remediação gerada pelo EIGAN — REVISE antes de aplicar.\n"
    "# NÃO aplique automaticamente em sistemas de terceiros; valide o escopo e as\n"
    "# variáveis (ex.: allowed_cidr). Este playbook NÃO é executado pelo produto.\n"
)


@dataclass
class RemediationArtifact:
    """Um artefato de correção revisável (nunca aplicado pelo produto)."""

    format: str  # "ansible"
    filename: str
    content: str
    title: str
    applies_to: str
    reviewable: bool = True


def _port_of(asset: str) -> int | None:
    m = _PORT_RE.search(asset)
    if not m:
        return None
    p = int(m.group(1))
    return p if 0 < p <= 65535 else None


def _host_of(asset: str) -> str:
    m = _PORT_RE.search(asset)
    return asset[: m.start()] if m else asset


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:48] or "finding"


def _yaml_str(value: str) -> str:
    """Escapa uma string para uso seguro entre aspas duplas em YAML."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


# --------------------------------------------------------------------------- #
# Templates determinísticos (matcher → builder).
# --------------------------------------------------------------------------- #
def _match_exposed_service(finding: Finding) -> bool:
    port = _port_of(finding.affected_asset)
    return port in _SENSITIVE_PORTS


def _build_exposed_service(finding: Finding) -> RemediationArtifact:
    port = _port_of(finding.affected_asset)
    assert port is not None
    service = _SENSITIVE_PORTS[port]
    host = _host_of(finding.affected_asset)
    play = f"""{_SAFETY_HEADER}---
# Restringe a exposição de {service} (porta {port}) a uma rede confiável.
# Ajuste `allowed_cidr` para o(s) bloco(s) autorizado(s) antes de aplicar.
- name: Restringir exposição de {service} (porta {port}) em {host}
  hosts: {_yaml_str(host)}
  become: true
  vars:
    allowed_cidr: "10.0.0.0/8"   # AJUSTAR: rede administrativa autorizada
  tasks:
    - name: Permitir {service} apenas da rede confiável
      community.general.ufw:
        rule: allow
        port: "{port}"
        proto: tcp
        src: "{{{{ allowed_cidr }}}}"

    - name: Bloquear {service} para qualquer outra origem
      community.general.ufw:
        rule: deny
        port: "{port}"
        proto: tcp
"""
    return RemediationArtifact(
        format="ansible",
        filename=f"remediate-{port}-{_slug(service)}-{_slug(host)}.yml",
        content=play,
        title=f"Restringir {service} exposto (porta {port})",
        applies_to=finding.affected_asset,
    )


def _match_security_headers(finding: Finding) -> bool:
    t = finding.title.lower()
    return any(k in t for k in ("hsts", "security header", "cabeçalho", "x-frame", "csp"))


def _build_security_headers(finding: Finding) -> RemediationArtifact:
    host = _host_of(finding.affected_asset)
    play = f"""{_SAFETY_HEADER}---
# Adiciona cabeçalhos de segurança HTTP no nginx. Revise o server_name/paths.
- name: Adicionar cabeçalhos de segurança em {host}
  hosts: {_yaml_str(host)}
  become: true
  vars:
    conf_snippet: /etc/nginx/conf.d/security-headers.conf
  tasks:
    - name: Escrever snippet de cabeçalhos de segurança
      ansible.builtin.copy:
        dest: "{{{{ conf_snippet }}}}"
        content: |
          add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
          add_header X-Content-Type-Options "nosniff" always;
          add_header X-Frame-Options "DENY" always;
          add_header Referrer-Policy "no-referrer" always;
      notify: reload nginx

  handlers:
    - name: reload nginx
      ansible.builtin.service:
        name: nginx
        state: reloaded
"""
    return RemediationArtifact(
        format="ansible",
        filename=f"remediate-headers-{_slug(host)}.yml",
        content=play,
        title="Adicionar cabeçalhos de segurança HTTP",
        applies_to=finding.affected_asset,
    )


# ordem estável: o primeiro matcher que casa gera o artefato.
_RULES: list[tuple[Callable[[Finding], bool], Callable[[Finding], RemediationArtifact]]] = [
    (_match_exposed_service, _build_exposed_service),
    (_match_security_headers, _build_security_headers),
]


def generate(finding: Finding) -> RemediationArtifact | None:
    """Artefato de remediação para o finding, ou ``None`` se não há template.

    ``None`` é honesto (scaffold): o tipo de finding ainda não tem correção
    gerável — o chamador deve reportar isso, nunca fabricar um playbook genérico.
    """
    for matches, build in _RULES:
        if matches(finding):
            return build(finding)
    return None


def generate_all(findings: list[Finding]) -> tuple[list[RemediationArtifact], list[Finding]]:
    """Gera artefatos para todos os findings com template. Retorna
    ``(artefatos, sem_template)`` — o segundo é reportado como pendente (honesto)."""
    artifacts: list[RemediationArtifact] = []
    uncovered: list[Finding] = []
    for f in findings:
        art = generate(f)
        if art is None:
            uncovered.append(f)
        else:
            artifacts.append(art)
    return artifacts, uncovered
