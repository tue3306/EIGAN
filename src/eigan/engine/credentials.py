"""Credenciais de FERRAMENTA — declarativas, honestas e sem invenção (§3.1/§13).

O EIGAN já gerencia a chave da **IA** (``ai/provider.py`` + menu). Faltava o
análogo para as **ferramentas**: muitas rendem muito mais (ou só rendem) com uma
chave/licença — ``wpscan`` sem ``WPSCAN_API_TOKEN`` não consulta CVEs conhecidas;
``subfinder`` sem as fontes OSINT (Shodan/Censys/VirusTotal/SecurityTrails) acha
uma fração dos subdomínios; e ferramentas **pagas/GUI** (ex.: Burp Suite Pro) não
são automatizáveis por um agente headless.

Este módulo dá o vocabulário declarativo para isso. Cada plugin declara, no
``metadata.yaml``, suas credenciais (``credentials:``) e o seu regime de
licenciamento (``licensing:``). O ``doctor`` mostra o estado por ferramenta, o
menu grava as chaves no ``.env`` (chmod 600, nunca ecoando), e o runtime **anota
cobertura parcial** quando uma chave opcional falta — nunca fingindo o que não foi
coletado (§3.1).

Regras: a chave vive **só** em env/arquivo (nunca commitada, nunca impressa). O
``env`` inheritance do subprocess (``engine/base.py``) já entrega as env vars às
ferramentas — este módulo é a camada declarativa + de diagnóstico em cima disso.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class Licensing(str, Enum):
    """Regime de licenciamento de uma ferramenta — dita como o agente a trata.

    - ``FREE``: gratuita, sem chave. Roda plenamente.
    - ``API_KEY``: gratuita/open-source, mas uma chave de API **opcional ou
      obrigatória** habilita/enriquece capacidades (ex.: wpscan, subfinder).
    - ``PAID``: comercial e/ou GUI (ex.: Burp Suite Pro). O agente **não a
      automatiza** — é declarada honestamente e nunca finge rodar (§3.6).
    """

    FREE = "free"
    API_KEY = "api_key"
    PAID = "paid"

    @classmethod
    def from_str(cls, value: object, default: "Licensing | None" = None) -> "Licensing":
        fallback = cls.FREE if default is None else default
        if isinstance(value, cls):
            return value
        if value is None:
            return fallback
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return fallback


@dataclass(frozen=True)
class ToolCredential:
    """Uma credencial que uma ferramenta usa (declarada no metadata).

    ``env`` é a variável de ambiente que a carrega (ou, para ferramentas que leem
    um arquivo de config próprio, a chave equivalente). ``required`` distingue a
    credencial **obrigatória** (sem ela a ferramenta não rende nada de útil) da
    **opcional** (sem ela, a cobertura é parcial — ``degrades`` descreve o quê).
    """

    env: str
    label: str
    required: bool = False
    obtain_url: str = ""
    degrades: str = ""
    #: para ferramentas que consomem um arquivo de config próprio (ex.: subfinder
    #: lê ``~/.config/subfinder/provider-config.yaml``), o nome da fonte/provider
    #: dentro desse arquivo. Vazio = a ferramenta lê direto da env var ``env``.
    provider: str = ""

    @classmethod
    def from_dict(cls, data: object) -> "ToolCredential | None":
        if not isinstance(data, dict):
            return None
        env = str(data.get("env", "")).strip()
        if not env:
            return None
        return cls(
            env=env,
            label=str(data.get("label", env)),
            required=bool(data.get("required", False)),
            obtain_url=str(data.get("obtain_url", "")),
            degrades=str(data.get("degrades", "")),
            provider=str(data.get("provider", "")),
        )


@dataclass(frozen=True)
class CredentialState:
    """Estado resolvido de uma credencial contra o ambiente atual."""

    credential: ToolCredential
    present: bool

    @property
    def missing_required(self) -> bool:
        return self.credential.required and not self.present

    @property
    def missing_optional(self) -> bool:
        return not self.credential.required and not self.present


def resolve_credentials(
    credentials: tuple[ToolCredential, ...],
    env: Mapping[str, str] | None = None,
) -> list[CredentialState]:
    """Resolve cada credencial contra ``env`` (default: ``os.environ``).

    Presença = variável definida e **não vazia** (uma env var vazia no ``.env``
    conta como ausente — foi o que o setup grava ao limpar um override)."""
    source = os.environ if env is None else env
    return [
        CredentialState(credential=c, present=bool((source.get(c.env) or "").strip()))
        for c in credentials
    ]


def coverage_warning(tool: str, states: list[CredentialState]) -> str | None:
    """Aviso de **cobertura parcial** quando faltam chaves opcionais (§3.1).

    Retorna uma frase honesta (o que NÃO foi coletado) ou ``None`` se está tudo
    presente. Nunca inventa o que a chave teria trazido — só nomeia a lacuna."""
    gaps = [s.credential for s in states if s.missing_optional]
    if not gaps:
        return None
    parts = [c.degrades or f"a fonte '{c.label}' não foi usada" for c in gaps]
    return f"{tool}: cobertura PARCIAL — " + "; ".join(parts)
