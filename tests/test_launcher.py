"""Testes do launcher raiz ``vulnforge.py`` (Missão 1 / ADR-0005+0006).

O launcher é carregado **por caminho**, sob um nome de módulo distinto, para não
colidir com o pacote ``vulnforge`` (mesmo nome do arquivo). Exercitamos os
helpers puros e o roteamento de ``main`` — criar venv / instalar deps de verdade
envolve rede e fica fora do teste unitário (é medido à parte, no README).
"""

import collections
import importlib.util
from pathlib import Path

_LAUNCHER = Path(__file__).resolve().parents[1] / "vulnforge.py"
_VI = collections.namedtuple("_VI", "major minor micro releaselevel serial")


def _load():
    spec = importlib.util.spec_from_file_location("vf_launcher", _LAUNCHER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


launcher = _load()


def _opts(**over):
    base = dict.fromkeys(
        ("with_tools", "with_ai", "reinstall", "no_venv", "serve", "dev", "help"), False
    )
    base.update(over)
    return base


# --------------------------------------------------------------------------- #
# Helpers puros
# --------------------------------------------------------------------------- #
def test_launcher_file_is_executable():
    assert _LAUNCHER.stat().st_mode & 0o111, "vulnforge.py precisa ser executável (chmod +x)"


def test_venv_python_posix(tmp_path, monkeypatch):
    monkeypatch.setattr(launcher.os, "name", "posix")
    assert launcher.venv_python(tmp_path) == tmp_path / "bin" / "python"


def test_venv_python_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(launcher.os, "name", "nt")
    assert launcher.venv_python(tmp_path) == tmp_path / "Scripts" / "python.exe"


def test_default_extras_include_pdf_and_tui():
    assert "pdf" in launcher._DEFAULT_EXTRAS
    assert "tui" in launcher._DEFAULT_EXTRAS


def test_install_spec_default_and_flags():
    assert launcher._install_spec(_opts()) == ".[pdf,tui]"
    assert "ai" in launcher._install_spec(_opts(with_ai=True))
    assert "dev" in launcher._install_spec(_opts(dev=True))


def test_check_python_ok(monkeypatch):
    monkeypatch.setattr(launcher.sys, "version_info", _VI(3, 11, 0, "final", 0))
    assert launcher._check_python() is True


def test_check_python_too_old(monkeypatch, capsys):
    monkeypatch.setattr(launcher.sys, "version_info", _VI(3, 10, 9, "final", 0))
    assert launcher._check_python() is False
    out = capsys.readouterr().out
    assert "3.11" in out and "python.org" in out


def test_package_importable_returns_bool():
    assert isinstance(launcher.package_importable(), bool)


def test_ensure_env_file_creates_from_example(tmp_path, monkeypatch):
    (tmp_path / ".env.example").write_text("KEY=value\n")
    monkeypatch.setattr(launcher, "ROOT", tmp_path)
    launcher.ensure_env_file()
    assert (tmp_path / ".env").read_text() == "KEY=value\n"


def test_ensure_env_file_keeps_existing(tmp_path, monkeypatch):
    (tmp_path / ".env.example").write_text("KEY=value\n")
    (tmp_path / ".env").write_text("PRESERVE=1\n")
    monkeypatch.setattr(launcher, "ROOT", tmp_path)
    launcher.ensure_env_file()
    assert (tmp_path / ".env").read_text() == "PRESERVE=1\n"


# --------------------------------------------------------------------------- #
# Parsing de flags do launcher
# --------------------------------------------------------------------------- #
def test_parse_flags_extracts_launcher_flags():
    opts, cli = launcher._parse_launcher_flags(["--with-tools", "scan", "x"])
    assert opts["with_tools"] is True
    assert cli == ["scan", "x"]
    assert opts["help"] is False


def test_parse_flags_help_first_is_launcher_help():
    opts, cli = launcher._parse_launcher_flags(["--help"])
    assert opts["help"] is True and cli == []


def test_parse_flags_help_after_subcommand_forwards():
    opts, cli = launcher._parse_launcher_flags(["doctor", "--help"])
    assert opts["help"] is False and cli == ["doctor", "--help"]


# --------------------------------------------------------------------------- #
# _run_phase_b: extras opcionais + hand-off para a CLI
# --------------------------------------------------------------------------- #
def test_run_phase_b_translates_serve(monkeypatch):
    monkeypatch.setattr(launcher, "_pdf_notice", lambda: None)
    calls = []
    monkeypatch.setattr(launcher, "run_app", lambda argv: calls.append(argv) or 0)
    launcher._run_phase_b(_opts(serve=True), [])
    assert calls == [["serve", "--open"]]


def test_run_phase_b_with_tools_runs_doctor_install(monkeypatch):
    monkeypatch.setattr(launcher, "_pdf_notice", lambda: None)
    calls = []
    monkeypatch.setattr(launcher, "run_app", lambda argv: calls.append(argv) or 0)
    launcher._run_phase_b(_opts(with_tools=True), [])
    assert calls == [["doctor", "--install"], []]


# --------------------------------------------------------------------------- #
# main: roteamento (sem instalar de verdade)
# --------------------------------------------------------------------------- #
def test_main_help_prints_and_exits(monkeypatch, capsys):
    assert launcher.main(["--help"]) == 0
    assert "Flags do launcher" in capsys.readouterr().out


def test_main_runs_app_when_importable(monkeypatch):
    monkeypatch.setattr(launcher, "package_importable", lambda: True)
    monkeypatch.setattr(launcher, "ensure_env_file", lambda: None)
    monkeypatch.setattr(launcher, "ensure_dirs", lambda: None)
    monkeypatch.setattr(launcher, "_pdf_notice", lambda: None)
    seen = {}

    def fake_run_app(argv):
        seen["argv"] = argv
        return 0

    monkeypatch.setattr(launcher, "run_app", fake_run_app)
    assert launcher.main(["doctor"]) == 0
    assert seen["argv"] == ["doctor"]


def test_main_bails_out_when_bootstrap_already_tried(monkeypatch):
    monkeypatch.setattr(launcher, "package_importable", lambda: False)
    monkeypatch.setattr(launcher, "ensure_env_file", lambda: None)
    monkeypatch.setattr(launcher, "ensure_dirs", lambda: None)
    monkeypatch.setenv(launcher._BOOTSTRAP_FLAG, "1")
    called = {}
    monkeypatch.setattr(launcher, "ensure_environment", lambda opts: called.setdefault("env", True))
    assert launcher.main([]) == 1
    assert "env" not in called  # não tentou preparar ambiente de novo


def test_main_bootstraps_then_reexecs(monkeypatch):
    monkeypatch.setattr(launcher, "package_importable", lambda: False)
    monkeypatch.setattr(launcher, "ensure_env_file", lambda: None)
    monkeypatch.setattr(launcher, "ensure_dirs", lambda: None)
    monkeypatch.delenv(launcher._BOOTSTRAP_FLAG, raising=False)
    fake_py = Path("/venv/bin/python")
    monkeypatch.setattr(launcher, "ensure_environment", lambda opts: fake_py)
    seen = {}
    monkeypatch.setattr(launcher, "_reexec", lambda py, argv: seen.update(py=py, argv=argv) or 7)
    assert launcher.main(["scan", "x"]) == 7
    assert seen == {"py": fake_py, "argv": ["scan", "x"]}


def test_main_returns_error_when_environment_unavailable(monkeypatch):
    monkeypatch.setattr(launcher, "package_importable", lambda: False)
    monkeypatch.setattr(launcher, "ensure_env_file", lambda: None)
    monkeypatch.setattr(launcher, "ensure_dirs", lambda: None)
    monkeypatch.delenv(launcher._BOOTSTRAP_FLAG, raising=False)
    monkeypatch.setattr(launcher, "ensure_environment", lambda opts: None)
    assert launcher.main([]) == 1
