"""Metadados de plugin e composição runner+metadata (:class:`PluginSpec`).

Separa *o que o plugin é* (declarativo, vindo de ``metadata.yaml``) de *como ele
executa* (:class:`~vulnforge.engine.base.BaseToolPlugin`). O registry
(``engine/registry.py``) lê o ``metadata.yaml``, instancia o runner e compõe os
dois num :class:`PluginSpec`, que é a unidade que o orquestrador consome.

Regra anti-invenção (§5): ``license``/``commercial_use`` marcados ``VERIFICAR``/
``verify`` NÃO são fato — devem ser confirmados na fonte oficial antes do release.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from ..capability import Capability, Category
from ..findings.schema import Finding
from ..perspective import Perspective
from .base import BaseToolPlugin


class PluginMetadataError(ValueError):
    """metadata.yaml ausente, malformado ou com campo obrigatório inválido."""


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


@dataclass(frozen=True)
class PluginMetadata:
    """Contrato declarativo de um plugin (carregado de ``metadata.yaml``)."""

    name: str
    category: Category
    capabilities: tuple[Capability, ...]
    supported_perspectives: tuple[Perspective, ...]
    tool: str                      # binário/ferramenta subjacente
    description: str = ""
    subcategory: str = ""          # recon | network | web | cloud | ...
    version_source: str = "# VERIFICAR"
    license: str = "VERIFICAR"     # não é fato até confirmado na fonte oficial
    commercial_use: str = "verify"  # ok | verify | restricted
    requires_credentials: bool = False
    chained_after: tuple[str, ...] = ()   # capabilities que rodam antes
    enabled_by_default: bool = True
    roadmap: bool = False          # scaffolded honesto: declarado, ainda não operante
    path: Path | None = None

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PluginMetadata":
        p = Path(path)
        try:
            data = yaml.safe_load(p.read_text()) or {}
        except yaml.YAMLError as exc:  # malformado
            raise PluginMetadataError(f"{p}: YAML inválido: {exc}") from exc
        if not isinstance(data, dict):
            raise PluginMetadataError(f"{p}: metadata.yaml deve ser um mapa.")

        try:
            name = str(data["name"])
            category = Category(str(data["category"]).strip().lower())
            caps_raw = data.get("capabilities") or ([data["capability"]]
                                                    if data.get("capability") else [])
            capabilities = tuple(Capability.from_str(c) for c in _as_list(caps_raw))
            if not capabilities:
                raise KeyError("capabilities")
            persp = tuple(
                Perspective(str(x).strip().lower())
                for x in (data.get("supported_perspectives") or ["external", "internal"])
            )
            tool = str(data["tool"])
        except KeyError as exc:
            raise PluginMetadataError(f"{p}: campo obrigatório ausente: {exc}") from exc
        except ValueError as exc:
            raise PluginMetadataError(f"{p}: valor inválido: {exc}") from exc

        return cls(
            name=name,
            category=category,
            capabilities=capabilities,
            supported_perspectives=persp,
            tool=tool,
            description=str(data.get("description", "")),
            subcategory=str(data.get("subcategory", "")),
            version_source=str(data.get("version_source", "# VERIFICAR")),
            license=str(data.get("license", "VERIFICAR")),
            commercial_use=str(data.get("commercial_use", "verify")),
            requires_credentials=bool(data.get("requires_credentials", False)),
            chained_after=tuple(_as_list(data.get("chained_after"))),
            enabled_by_default=bool(data.get("enabled_by_default", True)),
            roadmap=bool(data.get("roadmap", False)),
            path=p,
        )


@dataclass
class PluginSpec:
    """Runner + metadados. Unidade que o orquestrador executa.

    Delega decisões de ativação aos metadados (sem ``if`` de perspectiva no
    fluxo). O runner pode ser ``None`` quando o plugin é *roadmap* (scaffolded
    honesto): ele aparece no catálogo mas não executa.
    """

    metadata: PluginMetadata
    runner: BaseToolPlugin | None = None
    load_error: str = ""  # preenchido quando o plugin falhou ao carregar (degradado)

    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def degraded(self) -> bool:
        return bool(self.load_error)

    def provides(self, capability: Capability) -> bool:
        return capability in self.metadata.capabilities

    def runs_in(self, perspective: Perspective) -> bool:
        return perspective in self.metadata.supported_perspectives

    def available(self) -> bool:
        """Executável presente E plugin operante (não roadmap, não degradado)."""
        if self.metadata.roadmap or self.runner is None or self.degraded:
            return False
        return self.runner.available()

    def scan(self, target: str, **options) -> list[Finding]:
        if self.runner is None:
            return []
        return self.runner.scan(target, **options)
