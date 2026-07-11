"""Classe de destrutividade — conceito de 1ª classe (CLAUDE.md §4.1).

Toda capacidade/ferramenta/ação declara uma :class:`ImpactClass`. O Policy Engine
usa a classe (+ perspectiva + escopo + perfil) para decidir determinística e
auditável se a ação roda sozinha, exige aprovação humana ou é recusada.
"""

from __future__ import annotations

from enum import Enum


class ImpactClass(str, Enum):
    """Escala de destrutividade, do menos ao mais intrusivo."""

    PASSIVE = "passive"  # OSINT, DNS, cert transparency, leitura de feeds
    ACTIVE_SAFE = "active_safe"  # port scan, banner grab, httpx, template não-intrusivo
    ACTIVE_INTRUSIVE = "active_intrusive"  # fuzzing pesado, brute-force leve, enum autenticada
    EXPLOIT_VALIDATION = "exploit_validation"  # PoC/validação de exploração autorizada
    STATE_CHANGING = "state_changing"  # escreve/altera o alvo, remediação aplicada

    @property
    def rank(self) -> int:
        """Ordem crescente de destrutividade (para comparação com o teto)."""
        return _ORDER[self]

    @property
    def label(self) -> str:
        return _LABELS[self]

    @classmethod
    def from_str(cls, value: str | None, *, default: "ImpactClass") -> "ImpactClass":
        """Normaliza um valor de metadata (`impact_class:`); desconhecido → default."""
        if not value:
            return default
        try:
            return cls(value.strip().lower())
        except ValueError:
            return default


_ORDER: dict[ImpactClass, int] = {
    ImpactClass.PASSIVE: 0,
    ImpactClass.ACTIVE_SAFE: 1,
    ImpactClass.ACTIVE_INTRUSIVE: 2,
    ImpactClass.EXPLOIT_VALIDATION: 3,
    ImpactClass.STATE_CHANGING: 4,
}

_LABELS: dict[ImpactClass, str] = {
    ImpactClass.PASSIVE: "passiva (OSINT/leitura)",
    ImpactClass.ACTIVE_SAFE: "ativa segura (scan não-intrusivo)",
    ImpactClass.ACTIVE_INTRUSIVE: "ativa intrusiva (fuzzing/brute leve)",
    ImpactClass.EXPLOIT_VALIDATION: "validação de exploração (autorizada)",
    ImpactClass.STATE_CHANGING: "altera estado do alvo",
}
