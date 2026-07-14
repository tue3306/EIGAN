"""Metadados de plugin e composição runner+metadata (:class:`PluginSpec`).

Separa *o que o plugin é* (declarativo, vindo de ``metadata.yaml``) de *como ele
executa* (:class:`~eigan.engine.base.BaseToolPlugin`). O registry
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
from ..policy.impact import ImpactClass
from .base import BaseToolPlugin
from .cascade import CascadeRule
from .credentials import CredentialState, Licensing, ToolCredential, resolve_credentials


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
    tool: str  # binário/ferramenta subjacente
    description: str = ""
    subcategory: str = ""  # recon | network | web | cloud | ...
    version_source: str = "# VERIFICAR"
    license: str = "VERIFICAR"  # não é fato até confirmado na fonte oficial
    commercial_use: str = "verify"  # ok | verify | restricted
    requires_credentials: bool = False
    # Credenciais de FERRAMENTA (ADR-0013) — declarativas: quais chaves/env vars a
    # ferramenta usa, obrigatórias ou opcionais (degradam a cobertura). Vazio =
    # ferramenta sem chave. Ver ``engine/credentials.py``.
    credentials: tuple[ToolCredential, ...] = ()
    # Regime de licenciamento: free | api_key | paid. ``paid`` (Burp) marca a
    # ferramenta como NÃO automatizável — declarada honestamente (§3.6).
    licensing: Licensing = Licensing.FREE
    chained_after: tuple[str, ...] = ()  # capabilities que rodam antes
    enabled_by_default: bool = True
    roadmap: bool = False  # scaffolded honesto: declarado, ainda não operante
    install_hint: str = ""  # como instalar a ferramenta (usado por `doctor`)
    # Sinais de seleção (ADR-0007) — heurísticas operacionais NOSSAS (não fatos
    # externos): guiam o Tool Selection Engine a escolher entre ferramentas que
    # provêem a mesma capability. Primitivos e imutáveis (sem dep. da camada
    # cognitiva). Vêm do bloco ``selection:`` do metadata; defaults honestos.
    sel_speed: str = "medium"  # low | medium | high
    sel_accuracy: str = "medium"
    sel_resource: str = "medium"
    sel_preferred_when: tuple[str, ...] = ()  # tags de contexto que favorecem
    sel_avoid_when: tuple[str, ...] = ()  # tags que desfavorecem/excluem
    # Classe de destrutividade (ADR-0011): o Policy Engine usa isto para decidir
    # executar / pedir aprovação humana / recusar. Default conservador: ativa-segura.
    impact_class: ImpactClass = ImpactClass.ACTIVE_SAFE
    # Grafo de cascata (ADR-0004): regras que, dado um finding, sugerem disparar
    # outras ferramentas. Declarativo — a decisão vive no metadata, não no Core.
    triggers_on: tuple[CascadeRule, ...] = ()
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
            caps_raw = data.get("capabilities") or (
                [data["capability"]] if data.get("capability") else []
            )
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

        sel = data.get("selection") or {}
        if not isinstance(sel, dict):
            sel = {}

        def _rating(key: str) -> str:
            v = str(sel.get(key, "medium")).strip().lower()
            return v if v in {"low", "medium", "high"} else "medium"

        creds_raw = data.get("credentials") or []
        credentials: list[ToolCredential] = []
        if isinstance(creds_raw, list):
            for item in creds_raw:
                cred = ToolCredential.from_dict(item)
                if cred is not None:
                    credentials.append(cred)
        licensing = Licensing.from_str(data.get("licensing"))
        # requires_credentials é derivado (uma credencial obrigatória o implica),
        # mas um valor explícito no metadata vence.
        requires_creds = bool(
            data.get(
                "requires_credentials",
                any(c.required for c in credentials),
            )
        )

        triggers_raw = data.get("triggers_on") or []
        triggers: list[CascadeRule] = []
        if isinstance(triggers_raw, list):
            for item in triggers_raw:
                rule = CascadeRule.from_dict(item)
                if rule is not None:
                    triggers.append(rule)

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
            requires_credentials=requires_creds,
            credentials=tuple(credentials),
            licensing=licensing,
            chained_after=tuple(_as_list(data.get("chained_after"))),
            enabled_by_default=bool(data.get("enabled_by_default", True)),
            roadmap=bool(data.get("roadmap", False)),
            install_hint=str(data.get("install_hint", "")),
            sel_speed=_rating("speed"),
            sel_accuracy=_rating("accuracy"),
            sel_resource=_rating("resource_usage"),
            sel_preferred_when=tuple(_as_list(sel.get("preferred_when"))),
            sel_avoid_when=tuple(_as_list(sel.get("avoid_when"))),
            impact_class=ImpactClass.from_str(
                data.get("impact_class"), default=ImpactClass.ACTIVE_SAFE
            ),
            triggers_on=tuple(triggers),
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

    def credential_states(self, env=None) -> list[CredentialState]:
        """Estado das credenciais declaradas contra o ambiente (default: os.environ)."""
        return resolve_credentials(self.metadata.credentials, env)

    def coverage_note(self, env=None) -> str | None:
        """Aviso de cobertura parcial quando faltam chaves opcionais (§3.1)."""
        from .credentials import coverage_warning

        return coverage_warning(self.name, self.credential_states(env))

    def runs_in(self, perspective: Perspective) -> bool:
        # UNIFIED (modo produto) casa com qualquer plugin: um scan abrangente pode
        # usar tanto capacidades de recon externo quanto de rede interna, e a
        # seleção real por alvo é decidida pela estratégia/cascata, não pela
        # classe pública×privada do host.
        if perspective is Perspective.UNIFIED:
            return True
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
