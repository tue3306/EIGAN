"""Helpers de apresentação compartilhados pela CLI (menu, wizard, TUI).

Puro stdlib e **sem dependência de click** — retornam strings; quem chama decide
a cor (``click.secho``) ou o destino. Centralizar aqui garante que o menu, o
wizard e a TUI desenhem molduras idênticas (antes cada um tinha a sua, com
bordas desalinhadas).
"""

from __future__ import annotations

BOX_WIDTH = 58


def boxed(lines: list[str], width: int = BOX_WIDTH) -> str:
    """Emoldura ``lines`` numa caixa de linha dupla alinhada em qualquer terminal.

    O padding é calculado sobre o comprimento *visível* de cada linha, então
    linhas de tamanhos diferentes ficam com a borda direita alinhada (o bug do
    box manual do wizard antigo).
    """
    inner = width - 2
    top = "╔" + "═" * inner + "╗"
    bottom = "╚" + "═" * inner + "╝"
    body = ["║" + (" " + ln).ljust(inner) + "║" for ln in lines]
    return "\n".join([top, *body, bottom])


def rule(label: str = "", width: int = BOX_WIDTH) -> str:
    """Régua horizontal opcional com rótulo centralizado (``── Resumo ──``)."""
    if not label:
        return "─" * width
    pad = width - len(label) - 2
    left = pad // 2
    right = pad - left
    return f"{'─' * max(left, 0)} {label} {'─' * max(right, 0)}"
