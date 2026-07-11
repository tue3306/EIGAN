"""Consent gate — confirmação explícita do operador antes de scan ativo.

Complementa o guardrail de escopo (:mod:`eigan.security.scope`): o escopo
diz *o que* pode ser testado; o consent gate exige que um humano *afirme* a
autorização no momento da execução (ou via flag auditável em CI).
"""

from __future__ import annotations

from dataclasses import dataclass


class ConsentDenied(Exception):
    """Operador não confirmou a autorização."""


@dataclass
class ConsentGate:
    engagement: str
    targets: list[str]

    _BANNER = (
        "AVISO LEGAL: scanning ativo de vulnerabilidades sem autorização é ilegal "
        "em muitas jurisdições. Prossiga apenas contra alvos que você tem permissão "
        "documentada para testar."
    )

    def prompt_text(self) -> str:
        alvos = "\n  - ".join(self.targets)
        return (
            f"{self._BANNER}\n\n"
            f"Engajamento: {self.engagement}\n"
            f"Alvos autorizados:\n  - {alvos}\n\n"
            "Confirma que possui autorização por escrito para testar estes alvos?"
        )

    def require(self, *, assume_yes: bool = False, input_fn=input) -> None:
        """Bloqueia até confirmação. ``assume_yes`` (flag ``--yes`` em CI) registra
        consentimento não-interativo — deve ser usado apenas em pipelines
        auditáveis com autorização já registrada."""
        if assume_yes:
            return
        answer = input_fn(self.prompt_text() + " [digite 'yes' para prosseguir]: ")
        if answer.strip().lower() not in {"yes", "s", "sim"}:
            raise ConsentDenied("Consentimento não concedido; scan abortado.")
