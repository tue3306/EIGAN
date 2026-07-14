"""Testes do menu de produto (ADR-0005).

Exercita apresentação (banner/menu), roteamento resiliente e as ações
testáveis (histórico/configuração) com ``input_fn``/``echo`` injetados — sem
tocar em rede, TTY ou nos fluxos bloqueantes (wizard/serve).
"""

import importlib.util
import os
import sys
import types

import pytest

from eigan.cli import menu, tui
from eigan.findings.store import FindingStore


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
    assert "EIGAN" in b
    assert b.startswith("╔") and "╚" in b


def test_serve_app_opens_deeplink_path(monkeypatch):
    # O wizard abre o dashboard direto no scan concluído: serve_app deve repassar
    # ``open_path`` para a URL aberta no navegador (deep-link #/scan/<id>).
    opened: dict[str, str] = {}
    monkeypatch.setattr(
        menu, "_open_when_ready", lambda h, p, url, **_k: opened.setdefault("url", url)
    )
    monkeypatch.setitem(sys.modules, "uvicorn", types.SimpleNamespace(run=lambda *a, **k: None))
    menu.serve_app(db=":memory:", open_browser=True, open_path="/#/scan/9", echo=lambda *_a: None)
    assert opened["url"].endswith("/#/scan/9")


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
    monkeypatch.setenv("EIGAN_CONFIG_DIR", str(tmp_path))
    out: list[str] = []
    menu.action_config(db="x.db", input_fn=_feeder(["N"]), echo=out.append)
    text = "\n".join(out)
    assert "Configuração atual" in text
    assert "Banco de dados" in text
    assert "x.db" in text


def test_configure_ai_provider_writes_env_without_leaking_key(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for k in ("EIGAN_AI_PROVIDER", "GROQ_API_KEY", "GROQ_MODEL"):
        monkeypatch.delenv(k, raising=False)
    out: list[str] = []
    # escolhe Groq (5 na ordem: anthropic,openai,gemini,openrouter,groq,...) → chave → modelo
    from eigan.ai.provider import list_providers

    idx = [s.name for s in list_providers()].index("groq") + 1
    menu.configure_ai_provider(
        input_fn=_feeder([str(idx), "gsk-secret-key", "algum-modelo"]), echo=out.append
    )
    env = (tmp_path / ".env").read_text()
    assert "GROQ_API_KEY=gsk-secret-key" in env  # gravado no .env (fora do git)
    assert "EIGAN_AI_PROVIDER=groq" in env
    assert "gsk-secret-key" not in "\n".join(out)  # a chave NUNCA é ecoada
    assert os.environ["GROQ_API_KEY"] == "gsk-secret-key"  # aplicado na sessão


def test_configure_ai_provider_skip_writes_no_env_and_warns_scan_refused(tmp_path, monkeypatch):
    # Pular a configuração é permitido (para ver dashboard/relatórios/histórico),
    # mas a mensagem é honesta (AI-native, §3.4): o scan exige um provedor — não
    # existe "modo determinístico" que rode um scan sem IA.
    monkeypatch.chdir(tmp_path)
    out: list[str] = []
    menu.configure_ai_provider(input_fn=_feeder(["0"]), echo=out.append)
    assert not (tmp_path / ".env").exists()
    joined = "\n".join(out).lower()
    assert "scan exige um provedor" in joined
    assert "sem ia" not in joined  # não promete mais "modo determinístico sem IA"


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
