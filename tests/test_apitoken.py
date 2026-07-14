"""Testes do token de API (ADR-0014): geração, persistência chmod 600, match."""

from __future__ import annotations

import os

from eigan.security import apitoken


def test_env_token_wins(monkeypatch):
    monkeypatch.setenv("EIGAN_API_TOKEN", "do-ambiente")
    assert apitoken.current_token() == "do-ambiente"
    assert apitoken.token_matches("do-ambiente")
    assert not apitoken.token_matches("outro")
    assert not apitoken.token_matches(None)


def test_generate_and_persist_chmod600(tmp_path, monkeypatch):
    monkeypatch.delenv("EIGAN_API_TOKEN", raising=False)
    monkeypatch.setenv("EIGAN_CONFIG_DIR", str(tmp_path))
    assert apitoken.current_token() is None  # nada ainda
    tok = apitoken.load_or_create_token()
    assert tok and len(tok) >= 20
    f = apitoken.token_file()
    assert f.exists()
    assert (os.stat(f).st_mode & 0o777) == 0o600  # só o dono lê
    # idempotente: relê o mesmo
    assert apitoken.load_or_create_token() == tok
    assert apitoken.current_token() == tok


def test_is_loopback():
    assert apitoken.is_loopback("127.0.0.1")
    assert apitoken.is_loopback("::1")
    assert apitoken.is_loopback("localhost")
    assert not apitoken.is_loopback("0.0.0.0")
    assert not apitoken.is_loopback("10.0.0.5")
    assert not apitoken.is_loopback(None)
