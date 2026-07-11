"""TUI full-screen (Textual) — a experiência *premium* da Missão 0 (ADR-0005).

Camada fina sobre :mod:`.menu`: apresenta o mesmo banner e as mesmas opções em
tela cheia e **despacha para as mesmíssimas ações** (nenhuma regra de negócio
duplicada). Textual é uma dependência **opcional** (extra ``[tui]``): todo o
``import textual`` acontece dentro de :func:`run_tui`, então importar este
módulo nunca falha — sem a lib (ou fora de um TTY), cai no menu numerado.

Cada seleção sai da tela cheia, roda a ação no console (reusando os fluxos
``click`` existentes: wizard, doctor, serve…) e reabre a TUI. É deliberadamente
simples e robusto: qualquer erro de terminal/CSS cai no ``fallback``.
"""

from __future__ import annotations

from typing import Callable

from . import menu


def run_tui(*, db: str = "eigan.db", fallback: Callable[[], int] | None = None) -> int:
    """Abre a TUI Textual. Sem Textual/TTY ou em erro, delega ao ``fallback``."""
    back = fallback or (lambda: menu.run_menu(db=db))
    try:
        from textual.app import App, ComposeResult
        from textual.binding import Binding
        from textual.widgets import Footer, Label, ListItem, ListView, Static
    except ImportError:
        return back()

    class EIGANTUI(App):  # type: ignore[misc,type-arg]  # Textual opcional
        TITLE = "EIGAN"
        CSS = """
        Screen { align: center middle; }
        #banner { padding: 1 2; content-align: center middle; }
        #menu { width: 74; border: round $accent; padding: 1 2; }
        ListItem { padding: 0 1; }
        """
        BINDINGS = [
            Binding("q", "quit", "Sair"),
            Binding("escape", "quit", "Sair"),
        ]

        def compose(self) -> "ComposeResult":
            yield Static(menu.banner(), id="banner")
            yield ListView(
                *[
                    ListItem(Label(f"{key})  {label}"), id=f"opt-{key}")
                    for key, label, _hint in menu._ITEMS
                ],
                id="menu",
            )
            yield Footer()

        def on_list_view_selected(self, event: "ListView.Selected") -> None:  # type: ignore[name-defined]
            item_id = event.item.id or ""
            self.exit(item_id.split("-", 1)[-1])

    while True:
        try:
            choice = EIGANTUI().run()
        except Exception:  # noqa: BLE001 — terminal/CSS problemático: cai no menu determinístico
            return back()

        if not choice or choice in menu._QUIT:
            return 0
        action = menu._DISPATCH.get(choice)
        if action is None:
            return 0
        try:
            action(db=db)
        except KeyboardInterrupt:
            pass
        try:
            input("\n↵  Enter para voltar ao menu… ")
        except EOFError:
            return 0
