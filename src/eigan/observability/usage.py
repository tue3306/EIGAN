"""Contagem de uso de tokens — telemetria **real**, nunca estimada (ADR-0025).

O número de tokens vem do **próprio provedor** (campo de uso da resposta HTTP), não
de heurística. :func:`extract_usage` normaliza os quatro formatos oficiais que o
EIGAN fala; :class:`UsageMeter` acumula de forma thread-safe; o medidor "corrente"
é escopável por execução via :func:`use_meter` (contextvar), com um medidor global
como padrão. Registrar é **best-effort**: uma falha aqui jamais derruba a chamada
de IA nem o scan.
"""

from __future__ import annotations

import contextvars
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field


def _nonneg_int(value: object) -> int:
    """Inteiro não-negativo ou 0 — tolera campo ausente/tipado errado do provedor."""
    if isinstance(value, bool):  # bool é subclasse de int — não conta como token
        return 0
    if isinstance(value, int) and value >= 0:
        return value
    return 0


@dataclass(frozen=True)
class TokenUsage:
    """Tokens de entrada (prompt) e saída (completion) de uma ou mais chamadas."""

    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def __add__(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            self.prompt_tokens + other.prompt_tokens,
            self.completion_tokens + other.completion_tokens,
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        }


def extract_usage(raw: object) -> TokenUsage | None:
    """Normaliza o bloco de uso de tokens da resposta de um provedor → TokenUsage.

    Formatos oficiais suportados (verificados na doc de cada provedor):

    * **OpenAI / Azure / compatíveis** — ``raw["usage"]`` com ``prompt_tokens`` e
      ``completion_tokens``.
    * **Anthropic** — ``raw["usage"]`` com ``input_tokens`` e ``output_tokens``.
    * **Google Gemini** — ``raw["usageMetadata"]`` com ``promptTokenCount`` e
      ``candidatesTokenCount``.
    * **Ollama** — no nível raiz, ``prompt_eval_count`` e ``eval_count``.

    Retorna ``None`` quando nenhum formato conhecido está presente — **nunca
    inventa** um número (§2/§3.1).
    """
    if not isinstance(raw, dict):
        return None

    usage = raw.get("usage")
    if isinstance(usage, dict):
        if "prompt_tokens" in usage or "completion_tokens" in usage:  # OpenAI-compat
            return TokenUsage(
                _nonneg_int(usage.get("prompt_tokens")),
                _nonneg_int(usage.get("completion_tokens")),
            )
        if "input_tokens" in usage or "output_tokens" in usage:  # Anthropic
            return TokenUsage(
                _nonneg_int(usage.get("input_tokens")),
                _nonneg_int(usage.get("output_tokens")),
            )

    meta = raw.get("usageMetadata")  # Google Gemini
    if isinstance(meta, dict) and ("promptTokenCount" in meta or "candidatesTokenCount" in meta):
        return TokenUsage(
            _nonneg_int(meta.get("promptTokenCount")),
            _nonneg_int(meta.get("candidatesTokenCount")),
        )

    if "prompt_eval_count" in raw or "eval_count" in raw:  # Ollama
        return TokenUsage(
            _nonneg_int(raw.get("prompt_eval_count")),
            _nonneg_int(raw.get("eval_count")),
        )

    return None


@dataclass(frozen=True)
class UsageEvent:
    """Uma chamada de IA medida: quem, qual modelo, quanto e para quê."""

    provider: str
    model: str
    usage: TokenUsage
    purpose: str = "ai"
    at: float = field(default_factory=time.time)


class UsageMeter:
    """Acumulador thread-safe de :class:`UsageEvent`.

    Sem I/O e sem locks longos: seguro para ser chamado de dentro de qualquer
    provedor. As leituras devolvem cópias/snapshots para não vazar o estado interno.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: list[UsageEvent] = []

    def record(self, event: UsageEvent) -> None:
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> list[UsageEvent]:
        with self._lock:
            return list(self._events)

    def call_count(self) -> int:
        with self._lock:
            return len(self._events)

    def total(self) -> TokenUsage:
        with self._lock:
            acc = TokenUsage()
            for event in self._events:
                acc = acc + event.usage
            return acc

    def by_model(self) -> dict[str, TokenUsage]:
        """Uso agregado por ``"<provider>:<model>"`` — para o dashboard/relatório."""
        with self._lock:
            agg: dict[str, TokenUsage] = {}
            for event in self._events:
                key = f"{event.provider}:{event.model}"
                agg[key] = agg.get(key, TokenUsage()) + event.usage
            return agg

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


# Medidor "corrente": global por padrão, escopável por execução via use_meter().
_default_meter = UsageMeter()
_current: contextvars.ContextVar[UsageMeter] = contextvars.ContextVar("eigan_usage_meter")


def current_meter() -> UsageMeter:
    """O medidor ativo no contexto atual (o global, se nenhum foi escopado)."""
    return _current.get(_default_meter)


@contextmanager
def use_meter(meter: UsageMeter) -> Iterator[UsageMeter]:
    """Escopa um medidor para o bloco (ex.: um scan agrega só o seu próprio uso)."""
    token = _current.set(meter)
    try:
        yield meter
    finally:
        _current.reset(token)


def record_completion(
    provider: str, model: str, raw: object, *, purpose: str = "ai"
) -> TokenUsage | None:
    """Extrai o uso de ``raw`` e registra no medidor corrente. Best-effort.

    Devolve o :class:`TokenUsage` extraído (ou ``None`` se o provedor não reportou
    uso). Nunca levanta: observabilidade não pode derrubar a chamada de IA.
    """
    usage = extract_usage(raw)
    if usage is None:
        return None
    current_meter().record(UsageEvent(provider=provider, model=model, usage=usage, purpose=purpose))
    return usage
