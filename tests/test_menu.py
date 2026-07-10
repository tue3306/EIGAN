"""Testes do menu de produto (ADR-0005).

Exercita apresentação (banner/menu), roteamento resiliente e as ações
testáveis (histórico/configuração) com ``input_fn``/``echo`` injetados — sem
tocar em rede, TTY ou nos fluxos bloqueantes (wizard/serve).
"""

import importlib.util

import pytest

from vulnforge.cli import menu, tui
from vulnforge.findings.store import FindingStore


def _feeder(answers):
    """input_fn falso: entrega respostas em ordem; esgotado, sinaliza EOF."""
    it = iter(answers)

    def _input(_prompt=""):
        try:
            return next(it)
        except StopIteration as exc:
            raise EOFError from exc

    return _input


# --------------------------------------------------------------------------- #
# Apresentação
# --------------------------------------------------------------------------- #
def test_banner_has_box_and_name():
    b = menu.banner()
    assert "VulnForge" in b
    assert b.startswith("╔") and "╚" in b


def test_render_menu_lists_all_options():
    m = menu.render_menu()
    for label in (
        "Novo Scan",
        "Dashboard",
        "Histórico",
        "Configuração",
        "Doctor",
        "Atualizar Ferramentas",
        "Sair",
    ):
        assert label in m


# --------------------------------------------------------------------------- #
# Loop / roteamento
# --------------------------------------------------------------------------- #
def test_run_menu_dispatches_then_quits(monkeypatch):
    called = []
    monkeypatch.setitem(menu._DISPATCH, "5", lambda **_: called.append("acao"))
    out: list[str] = []
    rc = menu.run_menu(db=":memory:", input_fn=_feeder(["5", "7"]), echo=out.append)
    assert rc == 0
    assert called == ["acao"]
    assert any("Até logo" in line for line in out)


def test_run_menu_rejects_invalid_option():
    out: list[str] = []
    rc = menu.run_menu(db=":memory:", input_fn=_feeder(["99", "7"]), echo=out.append)
    assert rc == 0
    assert any("inválida" in line for line in out)


def test_run_menu_eof_returns_zero():
    rc = menu.run_menu(db=":memory:", input_fn=_feeder([]), echo=lambda *_: None)
    assert rc == 0


def test_run_menu_swallows_action_errors(monkeypatch):
    def boom(**_):
        raise RuntimeError("falha simulada")

    monkeypatch.setitem(menu._DISPATCH, "5", boom)
    out: list[str] = []
    menu.run_menu(db=":memory:", input_fn=_feeder(["5", "7"]), echo=out.append)
    # Menu resiliente: erro acionável, nunca stack trace cru (CLAUDE.md §13).
    assert any("Erro:" in line and "falha simulada" in line for line in out)


# --------------------------------------------------------------------------- #
# Histórico
# --------------------------------------------------------------------------- #
def test_action_history_empty(tmp_path):
    out: list[str] = []
    menu.action_history(db=str(tmp_path / "v.db"), input_fn=_feeder([""]), echo=out.append)
    assert any("Nenhum scan" in line for line in out)


def test_action_history_lists_scans(tmp_path):
    db = str(tmp_path / "v.db")
    store = FindingStore(db)
    sid = store.create_scan("ad-hoc:example.com", "standard", ["example.com"])
    store.finish_scan(sid)
    store.close()

    out: list[str] = []
    menu.action_history(db=db, input_fn=_feeder([""]), echo=out.append)
    text = "\n".join(out)
    assert "Scans recentes" in text
    assert "example.com" in text
    assert str(sid) in text


def test_action_history_rejects_unknown_id(tmp_path):
    db = str(tmp_path / "v.db")
    FindingStore(db).create_scan("e", "standard", ["a"])
    out: list[str] = []
    menu.action_history(db=db, input_fn=_feeder(["999"]), echo=out.append)
    assert any("inexistente" in line for line in out)


# --------------------------------------------------------------------------- #
# Configuração
# --------------------------------------------------------------------------- #
def test_action_config_reports_state(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNFORGE_CONFIG_DIR", str(tmp_path))
    out: list[str] = []
    menu.action_config(db="x.db", input_fn=_feeder([]), echo=out.append)
    text = "\n".join(out)
    assert "Configuração atual" in text
    assert "Banco de dados" in text
    assert "x.db" in text


# --------------------------------------------------------------------------- #
# Seleção de front-end (TUI opcional com fallback)
# --------------------------------------------------------------------------- #
def test_run_frontend_uses_menu_when_not_interactive(monkeypatch):
    monkeypatch.setattr(menu, "_is_interactive", lambda: False)
    seen = {}

    def fake_menu(**kw):
        seen["db"] = kw.get("db")
        return 0

    monkeypatch.setattr(menu, "run_menu", fake_menu)
    assert menu.run_frontend("data.db") == 0
    assert seen["db"] == "data.db"


def test_textual_available_returns_bool():
    assert isinstance(menu._textual_available(), bool)


def test_run_tui_falls_back_without_textual():
    if importlib.util.find_spec("textual") is not None:
        pytest.skip("textual instalada; caminho de fallback não é exercitado aqui")
    assert tui.run_tui(db="x", fallback=lambda: 123) == 123
