"""Custo de execução a partir de tokens — **nunca fabrica preço** (ADR-0025).

Preço de LLM é dado factual, que varia por provedor/modelo/contrato/região e muda
com o tempo. Pela regra de veracidade (§2) e anti-invenção (§3.1/§5), o EIGAN não
embute nenhuma tabela de preços: o operador declara os preços **que ele confirmou
na fonte oficial** em ``config/ai_pricing.yaml``, marcando cada entrada como
``verified: true``. Sem entrada verificada para um modelo, o custo é ``UNVERIFIED``
(``None``) — o EIGAN reporta os **tokens reais** e diz honestamente que não sabe o
preço, em vez de estimar.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .usage import TokenUsage


@dataclass(frozen=True)
class CostEstimate:
    """Custo calculado a partir de tokens reais e de um preço **verificado**."""

    amount: float
    currency: str
    verified: bool
    source: str = ""


def _default_pricing_path() -> Path:
    """`config/ai_pricing.yaml` na raiz do repo (fluxo git-clone/dev)."""
    # observability/ -> eigan/ -> src/ -> raiz do repo
    return Path(__file__).resolve().parents[3] / "config" / "ai_pricing.yaml"


class CostModel:
    """Converte :class:`TokenUsage` em custo usando preços verificados pelo operador.

    A tabela é ``{model_id: {input_per_1k, output_per_1k, currency, source,
    verified}}``. Só entradas com ``verified: true`` e preços numéricos produzem um
    :class:`CostEstimate`; qualquer outra situação devolve ``None`` (UNVERIFIED).
    """

    def __init__(self, prices: dict[str, Any] | None = None) -> None:
        self._prices: dict[str, Any] = prices or {}

    @classmethod
    def from_config(cls, path: str | Path | None = None) -> "CostModel":
        candidate = Path(path) if path is not None else _default_pricing_path()
        if not candidate.exists():
            return cls({})
        try:
            data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            return cls({})
        models = data.get("models") if isinstance(data, dict) else None
        return cls(models if isinstance(models, dict) else {})

    def cost_for(self, model: str, usage: TokenUsage) -> CostEstimate | None:
        """Custo de ``usage`` para ``model`` — ``None`` se o preço não foi verificado."""
        entry = self._prices.get(model)
        if not isinstance(entry, dict) or not entry.get("verified"):
            return None  # UNVERIFIED — jamais estima
        try:
            input_per_1k = float(entry["input_per_1k"])
            output_per_1k = float(entry["output_per_1k"])
        except (KeyError, TypeError, ValueError):
            return None
        amount = (usage.prompt_tokens / 1000.0) * input_per_1k + (
            usage.completion_tokens / 1000.0
        ) * output_per_1k
        return CostEstimate(
            amount=round(amount, 6),
            currency=str(entry.get("currency", "USD")),
            verified=True,
            source=str(entry.get("source", "")),
        )
