"""Capabilities — o contrato central da arquitetura de plugins.

Pense em **capacidades, não em ferramentas** (ADR-0001). Uma :class:`Capability`
descreve *o que* é feito (ex.: descobrir portas, sondar web, rodar templates de
vulnerabilidade); um plugin descreve *como*, com qual ferramenta. Ferramentas que
provêem a mesma capability são **intercambiáveis**: trocar uma não afeta nada
acima da camada de plugin.

Módulo puro (só stdlib) — é domínio e não conhece infraestrutura, para ser
importável por qualquer camada sem ciclo.
"""

from __future__ import annotations

from enum import Enum


class Category(str, Enum):
    """Domínio operacional de um plugin (§B do produto)."""

    RED = "red"        # ofensivo: recon, enumeração, web, rede, exploração autorizada
    BLUE = "blue"      # defensivo: compliance, hardening, inventário, detecção
    PURPLE = "purple"  # correlação ATT&CK, gap analysis, validação de controles


class Capability(str, Enum):
    """Capacidade técnica que um plugin oferece.

    O pipeline (``engine/pipeline.py``) é escrito em cima destes valores; o
    registry resolve *quais plugins* os implementam. Novas capacidades são
    adicionadas aqui + referenciadas por um estágio — sem tocar no orquestrador.

    Grupos:
      - recon: superfície externa passiva/ativa;
      - network: descoberta e enumeração de host/porta/serviço;
      - web: cadeia de aplicação web;
      - cloud: exposição de armazenamento/APIs em nuvem;
      - blue: auditoria defensiva;
      - purple: correlação ofensivo×defensivo.
    """

    # ── recon ────────────────────────────────────────────────────────────────
    SUBDOMAIN_ENUMERATION = "subdomain_enumeration"
    DNS_RESOLUTION = "dns_resolution"

    # ── network ──────────────────────────────────────────────────────────────
    HOST_DISCOVERY = "host_discovery"
    PORT_DISCOVERY = "port_discovery"
    SERVICE_DETECTION = "service_detection"

    # ── web ──────────────────────────────────────────────────────────────────
    WEB_PROBE = "web_probe"                 # fingerprint HTTP/tecnologias/WAF
    SCREENSHOT = "screenshot"
    WEB_CRAWL = "web_crawl"
    PARAM_DISCOVERY = "param_discovery"
    VULN_TEMPLATE_SCAN = "vuln_template_scan"
    CMS_SCAN = "cms_scan"
    TLS_ASSESSMENT = "tls_assessment"

    # ── cloud ────────────────────────────────────────────────────────────────
    CLOUD_STORAGE_ENUM = "cloud_storage_enum"

    # ── blue (defensivo) ─────────────────────────────────────────────────────
    COMPLIANCE_AUDIT = "compliance_audit"   # mapeável a CIS/NIST
    HARDENING_AUDIT = "hardening_audit"
    IOC_INVENTORY = "ioc_inventory"

    @classmethod
    def from_str(cls, value: str) -> "Capability":
        """Resolve a partir do ``metadata.yaml`` (aceita o valor exato do enum)."""
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            raise ValueError(
                f"Capability desconhecida: {value!r}. Válidas: "
                f"{[c.value for c in cls]}"
            ) from exc
