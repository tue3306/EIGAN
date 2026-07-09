"""Pipeline de scan como grafo de estágios, parametrizado pela perspectiva.

Cada estágio agrupa ferramentas que podem rodar em paralelo; os estágios são
executados em ordem (o encadeamento lógico do recon → probe → vuln). As
ferramentas são referenciadas por nome; o orquestrador resolve o que existe no
registry, está disponível e suporta a perspectiva — o resto é pulado com
registro (a falha/ausência de uma ferramenta não derruba o pipeline).

Esta é a fonte declarativa dos pipelines EXTERNAL e INTERNAL (Parte 4).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..perspective import Perspective


@dataclass(frozen=True)
class Stage:
    name: str
    tools: tuple[str, ...]
    parallel: bool = True


# EXTERNAL: OSINT/superfície → validação → portas → web → crawl → params → vuln.
_EXTERNAL: tuple[Stage, ...] = (
    Stage("subdomain", ("subfinder", "amass")),
    Stage("resolve", ("dnsx",)),
    Stage("ports", ("naabu", "masscan", "nmap")),
    Stage("web-probe", ("httpx", "whatweb", "wafw00f")),
    Stage("screenshot", ("gowitness",)),
    Stage("crawl", ("katana", "gau", "gf")),
    Stage("params", ("arjun", "gxss")),
    Stage("vuln-templates", ("nuclei", "dalfox", "sqlmap", "crlfuzz", "corsy",
                             "ssrfmap", "sstimap", "jwt_tool")),
    Stage("cms", ("cmseek", "wpscan", "joomscan", "droopescan")),
    Stage("tls", ("testssl",)),
    Stage("cloud-api", ("s3scanner", "kiterunner")),
)

# INTERNAL: descoberta de host no CIDR → portas/serviços → (auth) → web → vuln.
_INTERNAL: tuple[Stage, ...] = (
    Stage("host-discovery", ("nmap",)),
    Stage("ports", ("naabu", "nmap")),
    Stage("service-auth", ("nmap",)),   # NSE + scan autenticado se houver credencial
    Stage("web-probe", ("httpx",)),
    Stage("screenshot", ("gowitness",)),
    Stage("crawl", ("katana",)),
    Stage("vuln-templates", ("nuclei",)),
    Stage("tls", ("testssl",)),
    # gancho p/ módulos futuros: AD/Windows/Linux/Container assessment.
)

_PIPELINES: dict[Perspective, tuple[Stage, ...]] = {
    Perspective.EXTERNAL: _EXTERNAL,
    Perspective.INTERNAL: _INTERNAL,
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
