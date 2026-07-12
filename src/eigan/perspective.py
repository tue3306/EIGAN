"""Perspectiva (vantage point) — conceito de primeira classe do domínio.

A perspectiva muda o comportamento de TODO o pipeline: quais alvos o guardrail
aceita (público × privado), quais ferramentas rodam, o rate limit padrão e se
credenciais para scan autenticado são permitidas. Tudo isso é dirigido por
*configuração* (o mapa :data:`_PROFILES`), não por ``if`` espalhado pelo código.

Módulo puro (sem I/O): só depende da stdlib, para ser importável por qualquer
camada sem ciclo de dependência.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse


class Perspective(str, Enum):
    """De onde o scan é conduzido.

    Extensível: novas variações (ex.: ``ASSUMED_BREACH``, ``AUTHENTICATED``) são
    adicionadas como membros aqui + uma entrada em :data:`_PROFILES`. Ainda NÃO
    implementadas — reservadas de propósito (não há política definida para elas).
    """

    EXTERNAL = "external"
    INTERNAL = "internal"


class HostClass(str, Enum):
    """Classificação determinística de um host literal. ``HOSTNAME`` é o caso
    não-classificável sem DNS — tratado como permitido em ambas as perspectivas,
    tendo o escopo autorizado como backstop."""

    PUBLIC = "public"
    PRIVATE = "private"  # RFC1918 / IPv6 unique-local
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    HOSTNAME = "hostname"


@dataclass(frozen=True)
class PerspectiveProfile:
    """Comportamento associado a uma perspectiva. Dirige o guardrail e o
    orquestrador sem condicionais espalhadas."""

    description: str
    allowed_host_classes: frozenset[HostClass]
    default_rate_limit: int  # pacotes/req por segundo (default do perfil)
    allow_credentials: bool  # scan autenticado permitido?
    osint_subdomains: bool  # enumeração passiva de subdomínio faz sentido?


# Configuração central. EXTERNAL protege contra apontar scan pra dentro por
# engano (bloqueia RFC1918/loopback/link-local); INTERNAL protege contra "vazar"
# o scan pra internet (bloqueia IP público).
_PROFILES: dict[Perspective, PerspectiveProfile] = {
    Perspective.EXTERNAL: PerspectiveProfile(
        description="Visão de atacante na internet pública, sem credencial.",
        allowed_host_classes=frozenset({HostClass.PUBLIC, HostClass.HOSTNAME}),
        default_rate_limit=150,  # conservador: não derrubar produção exposta
        allow_credentials=False,
        osint_subdomains=True,
    ),
    Perspective.INTERNAL: PerspectiveProfile(
        description="Dentro da rede (assumed breach / VPN / host de assessment).",
        allowed_host_classes=frozenset(
            {HostClass.PRIVATE, HostClass.LOOPBACK, HostClass.LINK_LOCAL, HostClass.HOSTNAME}
        ),
        default_rate_limit=1000,  # mais agressivo permitido (ainda configurável)
        allow_credentials=True,
        osint_subdomains=False,  # já se está dentro; sem OSINT de subdomínio
    ),
}


def profile_for(perspective: Perspective) -> PerspectiveProfile:
    try:
        return _PROFILES[perspective]
    except KeyError as exc:  # perspectiva reservada/não implementada
        raise ValueError(
            f"Perspectiva {perspective.value!r} declarada mas sem política definida."
        ) from exc


def extract_host(target: str) -> str:
    """Extrai o host de um alvo que pode ser IP, hostname, host:port ou URL."""
    t = target.strip()
    if "://" in t:
        return urlparse(t).hostname or t
    # host:port (sem esquema); evita quebrar IPv6 entre colchetes
    if t.count(":") == 1 and "[" not in t:
        return t.split(":")[0]
    return t


def validate_target(target: str) -> str:
    """Valida a *forma* de um alvo antes de qualquer uso ativo (secure coding §5).

    Um alvo legítimo é IP, hostname, ``host:port`` ou URL. Ele **nunca** começa
    com ``-`` (a ferramenta o leria como uma flag — *argument injection*: ``nmap``
    interpretaria ``--script=...`` como execução de script) nem contém espaços ou
    caracteres de controle (um único token de ``argv`` não os tem). Esta é uma
    barreira determinística de defesa em profundidade: roda antes do gate de
    escopo, para que um alvo malformado nunca chegue ao ``build_args`` de um
    runner. Retorna o alvo normalizado (``strip``) ou levanta ``ValueError``.
    """
    t = target.strip()
    if not t:
        raise ValueError("alvo vazio")
    if t[0] == "-":
        raise ValueError(
            f"alvo inválido {target!r}: não pode começar com '-' "
            "(seria interpretado como argumento de ferramenta)."
        )
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in t):
        raise ValueError(f"alvo inválido {target!r}: contém espaço ou caractere de controle.")
    return t


def classify_host(host: str) -> HostClass:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return HostClass.HOSTNAME
    if ip.is_loopback:
        return HostClass.LOOPBACK
    if ip.is_link_local:
        return HostClass.LINK_LOCAL
    if ip.is_private:
        return HostClass.PRIVATE
    return HostClass.PUBLIC


def target_allowed(
    perspective: Perspective, target: str, *, override: bool = False
) -> tuple[bool, str]:
    """Decide se ``target`` é compatível com a ``perspective`` (público×privado).

    Retorna (permitido, motivo). ``override`` força a liberação (exige flag
    explícita na camada de chamada e deve ser logado)."""
    host = extract_host(target)
    hc = classify_host(host)
    profile = profile_for(perspective)

    if hc in profile.allowed_host_classes:
        return True, ""
    if override:
        return True, (
            f"OVERRIDE: alvo {hc.value} '{host}' liberado manualmente em "
            f"perspectiva {perspective.value}"
        )
    return False, (
        f"perspectiva {perspective.value} recusa alvo {hc.value} '{host}': "
        + (
            "scan externo não pode apontar para endereço privado/loopback."
            if perspective is Perspective.EXTERNAL
            else "scan interno não pode apontar para IP público (evita vazar para a internet)."
        )
    )
