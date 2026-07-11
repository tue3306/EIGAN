"""Agentes — especialidades que agrupam capacidades (ADR-0007).

Um :class:`Agent` é uma especialidade de segurança (Recon, Web, Cloud, AD…) que
**agrupa capacidades**. O engine roteia cada capacidade planejada ao agente dono.
Fronteira honesta (§6 do CLAUDE.md):

* **Recon** é real (``built=True``): executa a descoberta/enumeração externa via
  os plugins reais (subfinder → dnsx → naabu/nmap → httpx → nuclei).
* Web/Cloud/AD/Exploitation são **scaffold honesto** (``built=False``): declarados
  e visíveis no ``doctor``, porém *sugeridos, não executados* até serem
  construídos. Nunca fingem rodar.

O agente não escolhe ferramenta nem executa: quem escolhe é o Tool Selection
Engine; quem executa é o Execution Engine. O agente é a camada de *roteamento por
especialidade* — o que mantém o núcleo estável ao crescer para 100+ módulos.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...capability import Capability

C = Capability


@dataclass(frozen=True)
class Agent:
    """Especialidade que possui um conjunto de capacidades."""

    name: str
    description: str
    capabilities: frozenset[Capability]
    built: bool  # True = executa; False = scaffold honesto (sugerido, não executado)

    def owns(self, capability: Capability) -> bool:
        return capability in self.capabilities


def default_agents() -> list[Agent]:
    """Catálogo de agentes. Recon real; demais scaffold honesto (roadmap)."""
    return [
        Agent(
            name="recon",
            description="Descoberta e enumeração da superfície (outside-in/inside-out).",
            capabilities=frozenset(
                {
                    C.SUBDOMAIN_ENUMERATION,
                    C.DNS_RESOLUTION,
                    C.HOST_DISCOVERY,
                    C.PORT_DISCOVERY,
                    C.SERVICE_DETECTION,
                    C.WEB_PROBE,
                    C.TLS_ASSESSMENT,
                    C.VULN_TEMPLATE_SCAN,
                }
            ),
            built=True,
        ),
        Agent(
            name="network",
            description="Enumeração profunda de rede/serviços (SMB/Samba, NSE por serviço).",
            capabilities=frozenset({C.NSE_VULN_SCAN, C.SMB_ENUMERATION}),
            built=True,
        ),
        Agent(
            name="web",
            description="Cadeia de aplicação web (crawl, parâmetros, CMS, screenshot).",
            capabilities=frozenset({C.WEB_CRAWL, C.PARAM_DISCOVERY, C.CMS_SCAN, C.SCREENSHOT}),
            built=False,
        ),
        Agent(
            name="cloud",
            description="Exposição e auditoria de nuvem (buckets, APIs, configuração).",
            capabilities=frozenset({C.CLOUD_STORAGE_ENUM, C.CLOUD_AUDIT}),
            built=False,
        ),
        Agent(
            name="active-directory",
            description="Enumeração de Active Directory / identidade (assumed breach).",
            capabilities=frozenset({C.AD_ENUMERATION}),
            built=False,
        ),
        Agent(
            name="exploitation",
            description="Validação/exploração autorizada de vulnerabilidades.",
            capabilities=frozenset({C.EXPLOITATION}),
            built=False,
        ),
    ]


@dataclass
class AgentRegistry:
    """Indexa agentes por capacidade. Uma capacidade pertence a um único agente."""

    agents: list[Agent]

    def __post_init__(self) -> None:
        self._by_cap: dict[Capability, Agent] = {}
        for agent in self.agents:  # ordem estável: o primeiro declarante vence
            for cap in agent.capabilities:
                self._by_cap.setdefault(cap, agent)

    @classmethod
    def default(cls) -> "AgentRegistry":
        return cls(default_agents())

    def for_capability(self, capability: Capability) -> Agent | None:
        return self._by_cap.get(capability)

    def built(self) -> list[Agent]:
        return [a for a in self.agents if a.built]

    def scaffolds(self) -> list[Agent]:
        return [a for a in self.agents if not a.built]
