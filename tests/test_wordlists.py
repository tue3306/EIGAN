"""Testes da resolução de wordlists (ADR-0019): SecLists, fallback, perfil, env."""

from __future__ import annotations

from pathlib import Path

from eigan.engine import wordlists


def test_builtin_fallback_when_no_seclists(monkeypatch):
    monkeypatch.delenv("EIGAN_WORDLIST_DIR", raising=False)
    monkeypatch.setattr(wordlists, "_SECLISTS_ROOTS", ())  # simula SO sem SecLists
    monkeypatch.setattr(wordlists, "_SYSTEM_FALLBACKS", {"content": ()})
    choice = wordlists.resolve("content", "standard")
    assert choice.source == "builtin" and choice.reduced_coverage
    assert "reduzida" in choice.note().lower()


def test_builtin_lists_are_substantial():
    # a embutida precisa ser MUITO maior que a antiga (80 linhas).
    for kind in ("content", "params", "dns"):
        p = Path(wordlists._BUILTIN[kind])
        assert p.is_file()
        n = len([ln for ln in p.read_text().splitlines() if ln.strip()])
        assert n >= 150, f"{kind}: só {n} entradas"


def test_profile_size_mapping():
    assert wordlists._size_for("quick") == "small"
    assert wordlists._size_for("standard") == "medium"
    assert wordlists._size_for("deep") == "large"
    assert wordlists._size_for("desconhecido") == "medium"


def test_seclists_detected_via_env(tmp_path, monkeypatch):
    # monta uma árvore SecLists falsa e aponta EIGAN_WORDLIST_DIR para ela.
    rel = "Discovery/Web-Content/directory-list-2.3-medium.txt"
    f = tmp_path / rel
    f.parent.mkdir(parents=True)
    f.write_text("admin\nlogin\n")
    monkeypatch.setenv("EIGAN_WORDLIST_DIR", str(tmp_path))
    assert wordlists.seclists_root() == str(tmp_path)
    choice = wordlists.resolve("content", "standard")
    assert choice.source == "seclists" and choice.path == str(f)
    assert not choice.reduced_coverage


def test_summary_by_profile_three_lines():
    lines = wordlists.summary_by_profile("content")
    assert len(lines) == 3
    assert any("quick" in ln for ln in lines) and any("deep" in ln for ln in lines)
