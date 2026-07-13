"""Pipeline de scan como grafo de estágios, parametrizado pela perspectiva.

Cada estágio referencia **capabilities** (ADR-0001), não ferramentas: o
orquestrador resolve, via registry, quais *plugins* implementam cada capability,
estão disponíveis e suportam a perspectiva. Trocar a ferramenta que provê uma
capability não muda o pipeline. Estágios sem nenhum plugin disponível são
pulados com registro (não derrubam o fluxo).

Esta é a fonte declarativa dos pipelines EXTERNAL e INTERNAL.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..capability import Capability
from ..perspective import Perspective

C = Capability


@dataclass(frozen=True)
class Stage:
    name: str
    capabilities: tuple[Capability, ...]
    parallel: bool = True


# EXTERNAL: OSINT/superfície → validação → portas → web → crawl → params → vuln.
_EXTERNAL: tuple[Stage, ...] = (
    Stage("subdomain", (C.SUBDOMAIN_ENUMERATION,)),
    Stage("resolve", (C.DNS_RESOLUTION,)),
    Stage("ports", (C.PORT_DISCOVERY,)),
    Stage("web-probe", (C.WEB_PROBE,)),
    Stage("screenshot", (C.SCREENSHOT,)),
    Stage("crawl", (C.WEB_CRAWL,)),
    Stage("params", (C.PARAM_DISCOVERY,)),
    Stage("vuln-templates", (C.VULN_TEMPLATE_SCAN,)),
    Stage("cms", (C.CMS_SCAN,)),
    Stage("tls", (C.TLS_ASSESSMENT,)),
    Stage("cloud-api", (C.CLOUD_STORAGE_ENUM,)),
)

# INTERNAL: descoberta de host no CIDR → portas/serviços → (auth) → web → vuln.
_INTERNAL: tuple[Stage, ...] = (
    Stage("host-discovery", (C.HOST_DISCOVERY,)),
    Stage("ports", (C.PORT_DISCOVERY,)),
    Stage("service-auth", (C.SERVICE_DETECTION,)),  # NSE + scan autenticado se houver credencial
    Stage("web-probe", (C.WEB_PROBE,)),
    Stage("screenshot", (C.SCREENSHOT,)),
    Stage("crawl", (C.WEB_CRAWL,)),
    Stage("vuln-templates", (C.VULN_TEMPLATE_SCAN,)),
    Stage("tls", (C.TLS_ASSESSMENT,)),
    # gancho p/ módulos futuros: AD/Windows/Linux/Container assessment.
)

# UNIFIED (modo produto): une o recon externo com a descoberta de rede num único
# pipeline canônico. Descobre superfície pública (subdomínio/DNS/web) E hosts/portas/
# serviços — sem obrigar o usuário a escolher perspectiva. A cascata aprofunda a
# partir do que aparecer (ex.: porta 445 → SMB; WordPress → wpscan).
_UNIFIED: tuple[Stage, ...] = (
    Stage("subdomain", (C.SUBDOMAIN_ENUMERATION,)),
    Stage("resolve", (C.DNS_RESOLUTION,)),
    Stage("host-discovery", (C.HOST_DISCOVERY,)),
    Stage("ports", (C.PORT_DISCOVERY,)),
    Stage("service-auth", (C.SERVICE_DETECTION,)),
    Stage("web-probe", (C.WEB_PROBE,)),
    Stage("screenshot", (C.SCREENSHOT,)),
    Stage("crawl", (C.WEB_CRAWL,)),
    Stage("params", (C.PARAM_DISCOVERY,)),
    Stage("vuln-templates", (C.VULN_TEMPLATE_SCAN,)),
    Stage("web-server", (C.WEB_SERVER_SCAN,)),
    Stage("cms", (C.CMS_SCAN,)),
    Stage("tls", (C.TLS_ASSESSMENT,)),
    Stage("cloud-api", (C.CLOUD_STORAGE_ENUM,)),
)

_PIPELINES: dict[Perspective, tuple[Stage, ...]] = {
    Perspective.EXTERNAL: _EXTERNAL,
    Perspective.INTERNAL: _INTERNAL,
    Perspective.UNIFIED: _UNIFIED,
}

# Profiles restringem quais estágios rodam (None = todos os da perspectiva).
PROFILE_STAGES: dict[str, set[str] | None] = {
    "quick": {"subdomain", "resolve", "ports", "host-discovery"},
    "standard": None,
    "deep": None,
    "web-only": {"web-probe", "screenshot", "crawl", "params", "vuln-templates", "cms", "tls"},
    "network-only": {"host-discovery", "resolve", "ports", "service-auth", "tls"},
}


def stages_for(perspective: Perspective, profile: str = "standard") -> list[Stage]:
    if perspective not in _PIPELINES:
        raise ValueError(f"Sem pipeline definido para perspectiva {perspective.value!r}.")
    if profile not in PROFILE_STAGES:
        raise ValueError(f"Perfil desconhecido: {profile!r}. Opções: {list(PROFILE_STAGES)}")
    allowed = PROFILE_STAGES[profile]
    stages = _PIPELINES[perspective]
    if allowed is None:
        return list(stages)
    return [s for s in stages if s.name in allowed]
