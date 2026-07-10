"""Tool Selection Engine — escolhe *qual ferramenta* provê uma capacidade.

O Planner decide a **capacidade** ("preciso descobrir portas"); este módulo,
de forma **determinística e justificada**, escolhe **qual plugin** executá-la
naquele contexto (ADR-0007). A escolha nunca é fixa: pondera sinais operacionais
do `metadata.yaml` (`selection:`) + disponibilidade real + contexto (perspectiva,
tags de SO/serviço/tecnologia, preferência velocidade×precisão). Empate resolvido
por nome (estável/reproduzível). Toda escolha carrega ``reasons`` — nada de
caixa-preta (§3.4 do CLAUDE.md).

A IA **não** entra aqui: seleção de ferramenta é lógica pura.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

from ...capability import Capability
from ...perspective import Perspective
from ..plugin import PluginSpec


class Rating(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {Rating.LOW: 1, Rating.MEDIUM: 2, Rating.HIGH: 3}[self]

    @classmethod
    def of(cls, value: str) -> "Rating":
        try:
            return cls(value.strip().lower())
        except ValueError:
            return cls.MEDIUM


class Prefer(str, Enum):
    """O que priorizar ao empatar utilidade — derivado do perfil/profundidade."""

    SPEED = "speed"
    ACCURACY = "accuracy"
    BALANCED = "balanced"


@dataclass(frozen=True)
class SelectionSignals:
    """Sinais operacionais de um plugin (do bloco ``selection:`` do metadata)."""

    speed: Rating = Rating.MEDIUM
    accuracy: Rating = Rating.MEDIUM
    resource_usage: Rating = Rating.MEDIUM
    preferred_when: frozenset[str] = frozenset()
    avoid_when: frozenset[str] = frozenset()

    @classmethod
    def from_spec(cls, spec: PluginSpec) -> "SelectionSignals":
        m = spec.metadata
        return cls(
            speed=Rating.of(m.sel_speed),
            accuracy=Rating.of(m.sel_accuracy),
            resource_usage=Rating.of(m.sel_resource),
            preferred_when=frozenset(t.lower() for t in m.sel_preferred_when),
            avoid_when=frozenset(t.lower() for t in m.sel_avoid_when),
        )


@dataclass(frozen=True)
class SelectionContext:
    """Contexto que molda a escolha da ferramenta.

    ``tags`` acumula sinais do alvo/descoberta (ex.: ``{"linux","http","wordpress",
    "low_bandwidth"}``). ``prefer`` vem do perfil (quick→velocidade, deep→precisão).
    """

    perspective: Perspective
    tags: frozenset[str] = frozenset()
    prefer: Prefer = Prefer.BALANCED
    installed_only: bool = True  # só ferramentas presentes no host (execução real)

    def with_tags(self, extra: set[str]) -> "SelectionContext":
        return SelectionContext(
            perspective=self.perspective,
            tags=self.tags | frozenset(t.lower() for t in extra),
            prefer=self.prefer,
            installed_only=self.installed_only,
        )


@dataclass(frozen=True)
class ToolChoice:
    """A ferramenta escolhida + a justificativa e as alternativas (para o log)."""

    spec: PluginSpec
    score: float
    reasons: tuple[str, ...]
    alternatives: tuple[str, ...] = ()

    @property
    def tool(self) -> str:
        return self.spec.name


@dataclass(frozen=True)
class _Scored:
    spec: PluginSpec
    score: float
    reasons: tuple[str, ...]
    avoided: bool


# Pesos por modo de preferência: (velocidade, precisão, penalidade de recurso).
_WEIGHTS: dict[Prefer, tuple[float, float, float]] = {
    Prefer.BALANCED: (1.0, 1.0, 0.5),
    Prefer.SPEED: (2.0, 1.0, 1.0),
    Prefer.ACCURACY: (1.0, 2.0, 0.3),
}
_PREFERRED_BONUS = 2.0  # por tag de contexto favorável casada
_AVOID_PENALTY = 4.0  # por tag desfavorável casada


class CapabilityRegistryPort(Protocol):
    """Porta mínima que o selector consome (o `PluginRegistry` a satisfaz)."""

    def for_capability(
        self, capability: Capability, perspective: Perspective | None = None
    ) -> list[PluginSpec]: ...


@dataclass
class ToolSelector:
    """Escolhe o melhor plugin para uma capacidade num contexto — justificado."""

    registry: CapabilityRegistryPort
    candidates: dict[Capability, list[str]] = field(default_factory=dict)  # cache p/ log

    def select(self, capability: Capability, ctx: SelectionContext) -> ToolChoice | None:
        """Retorna a escolha ou ``None`` se nenhuma ferramenta disponível provê a
        capacidade (o chamador registra "sugerido, não executado")."""
        specs = self.registry.for_capability(capability, ctx.perspective)
        pool = [s for s in specs if s.available()] if ctx.installed_only else list(specs)
        self.candidates[capability] = [s.name for s in pool]
        if not pool:
            return None

        scored = [self._score(s, ctx) for s in pool]
        # avoid_when exclui apenas se houver alternativa não-evitada (senão, roda
        # com penalidade e a justificativa deixa isso explícito — honesto).
        non_avoided = [s for s in scored if not s.avoided]
        ranked = non_avoided or scored
        ranked.sort(key=lambda s: (-s.score, s.spec.name))

        best = ranked[0]
        alternatives = tuple(s.spec.name for s in ranked[1:])
        reasons = best.reasons
        if alternatives:
            reasons = (*reasons, f"preferido a {', '.join(alternatives)}")
        return ToolChoice(
            spec=best.spec, score=best.score, reasons=reasons, alternatives=alternatives
        )

    def _score(self, spec: PluginSpec, ctx: SelectionContext) -> _Scored:
        sig = SelectionSignals.from_spec(spec)
        w_speed, w_acc, w_res = _WEIGHTS[ctx.prefer]
        score = (
            w_speed * sig.speed.rank
            + w_acc * sig.accuracy.rank
            - w_res * (sig.resource_usage.rank - 1)
        )
        reasons: list[str] = []
        if sig.speed is Rating.HIGH:
            reasons.append("velocidade alta")
        if sig.accuracy is Rating.HIGH:
            reasons.append("precisão alta")
        if sig.resource_usage is Rating.LOW:
            reasons.append("baixo consumo de recursos")

        matched_pref = sorted(sig.preferred_when & ctx.tags)
        if matched_pref:
            score += _PREFERRED_BONUS * len(matched_pref)
            reasons.append("favorecido pelo contexto: " + ", ".join(matched_pref))

        matched_avoid = sorted(sig.avoid_when & ctx.tags)
        avoided = bool(matched_avoid)
        if avoided:
            score -= _AVOID_PENALTY * len(matched_avoid)
            reasons.append("desfavorecido pelo contexto: " + ", ".join(matched_avoid))

        if not reasons:
            reasons.append("perfil equilibrado (sem sinal distintivo)")
        if ctx.prefer is not Prefer.BALANCED:
            reasons.append(f"modo={ctx.prefer.value}")
        return _Scored(spec=spec, score=score, reasons=tuple(reasons), avoided=avoided)
