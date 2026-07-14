"""Testes dos helpers de apresentação da CLI (``eigan.cli.ui``)."""

from __future__ import annotations

from eigan.cli.ui import BOX_WIDTH, boxed, rule


def test_boxed_borders_and_uniform_width():
    out = boxed(["curta", "uma linha bem mais comprida que a primeira"])
    lines = out.splitlines()
    assert lines[0].startswith("╔") and lines[0].endswith("╗")
    assert lines[-1].startswith("╚") and lines[-1].endswith("╝")
    # Todas as linhas têm exatamente a mesma largura (o bug do box desalinhado).
    assert len({len(ln) for ln in lines}) == 1
    assert len(lines[0]) == BOX_WIDTH


def test_boxed_wraps_every_content_line():
    out = boxed(["a", "b", "c"])
    body = out.splitlines()[1:-1]
    assert len(body) == 3
    assert all(ln.startswith("║") and ln.endswith("║") for ln in body)


def test_rule_plain_and_labeled():
    assert rule() == "─" * BOX_WIDTH
    labeled = rule("Resumo")
    assert "Resumo" in labeled
    assert labeled.startswith("─") and labeled.endswith("─")
    assert len(labeled) == BOX_WIDTH
