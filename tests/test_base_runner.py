"""Testes do runner seguro base (subprocess: lista de args, timeout, decode robusto).

``BaseToolPlugin._run`` é a ÚNICA porta por onde um subprocess é disparado (§5),
então o tratamento de erro/timeout dele tem de ser à prova de saída malformada.
"""

from __future__ import annotations

import subprocess

import pytest

from eigan.engine.base import BaseToolPlugin, ToolNotAvailable


class _Fake(BaseToolPlugin):
    binary = "python3"  # garantidamente no PATH do ambiente de teste
    name = "fake"

    def build_args(self, target, **options):
        return [target]

    def parse(self, result, target):
        return []


def test_run_timeout_with_invalid_utf8_does_not_crash(monkeypatch):
    """Timeout cujo stdout parcial tem bytes UTF-8 inválidos não pode derrubar o
    runner com UnicodeDecodeError — deve retornar timed_out=True (decode tolerante)."""

    def _boom(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd=["python3"], timeout=1, output=b"parcial \xff\xfe")

    monkeypatch.setattr(subprocess, "run", _boom)
    result = _Fake()._run(["x"], timeout=1)
    assert result.timed_out is True
    assert result.exit_code == 124
    assert "parcial" in result.stdout  # bytes inválidos viram U+FFFD, sem crash


def test_run_timeout_with_str_output(monkeypatch):
    """No modo text=True o stdout parcial pode já vir como str — sem re-decode."""

    def _boom(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd=["python3"], timeout=1, output="parcial-str")

    monkeypatch.setattr(subprocess, "run", _boom)
    result = _Fake()._run(["x"], timeout=1)
    assert result.timed_out is True
    assert result.stdout == "parcial-str"


def test_run_timeout_with_no_output(monkeypatch):
    """Timeout sem nenhuma saída capturada não deve virar None nem crashar."""

    def _boom(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd=["python3"], timeout=1)

    monkeypatch.setattr(subprocess, "run", _boom)
    result = _Fake()._run(["x"], timeout=1)
    assert result.timed_out is True
    assert result.stdout == ""


def test_run_raises_when_binary_missing():
    class _Missing(_Fake):
        binary = "definitely-not-a-real-binary-eigan-xyz"

    with pytest.raises(ToolNotAvailable):
        _Missing()._run(["x"])
