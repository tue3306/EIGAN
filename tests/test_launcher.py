"""Testes do launcher raiz ``vulnforge.py`` (Missão 0 / ADR-0005).

O launcher é carregado **por caminho**, sob um nome de módulo distinto, para
não colidir com o pacote ``vulnforge`` (mesmo nome do arquivo). Só exercitamos
os helpers puros — criar venv de verdade / instalar deps envolve rede e fica de
fora do teste unitário.
"""

import importlib.util
from pathlib import Path

_LAUNCHER = Path(__file__).resolve().parents[1] / "vulnforge.py"


def _load():
    spec = importlib.util.spec_from_file_location("vf_launcher", _LAUNCHER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


launcher = _load()


def test_launcher_file_is_executable():
    assert _LAUNCHER.stat().st_mode & 0o111, "vulnforge.py precisa ser executável (chmod +x)"


def test_venv_python_posix(tmp_path, monkeypatch):
    monkeypatch.setattr(launcher.os, "name", "posix")
    assert launcher.venv_python(tmp_path) == tmp_path / "bin" / "python"


def test_venv_python_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(launcher.os, "name", "nt")
    assert launcher.venv_python(tmp_path) == tmp_path / "Scripts" / "python.exe"


def test_install_specs_prefer_tui_then_base():
    # Tenta a experiência premium primeiro; sempre com fallback para a base.
    assert launcher._INSTALL_SPECS[0] == ".[tui]"
    assert launcher._INSTALL_SPECS[-1] == "."


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


def test_main_runs_app_when_importable(monkeypatch):
    # Com o pacote importável, main() entrega direto ao app (sem bootstrap/venv).
    monkeypatch.setattr(launcher, "package_importable", lambda: True)
    monkeypatch.setattr(launcher, "ensure_env_file", lambda: None)
    seen = {}

    def fake_run_app(argv):
        seen["argv"] = argv
        return 0

    monkeypatch.setattr(launcher, "run_app", fake_run_app)
    assert launcher.main(["doctor"]) == 0
    assert seen["argv"] == ["doctor"]


def test_main_bails_out_when_bootstrap_already_tried(monkeypatch):
    # Se já reexecutamos com a flag e ainda assim não importa, é erro real (rc=1),
    # sem loop de bootstrap.
    monkeypatch.setattr(launcher, "package_importable", lambda: False)
    monkeypatch.setattr(launcher, "ensure_env_file", lambda: None)
    monkeypatch.setenv(launcher._BOOTSTRAP_FLAG, "1")
    called = {}
    monkeypatch.setattr(launcher, "ensure_environment", lambda: called.setdefault("env", True))
    assert launcher.main([]) == 1
    assert "env" not in called  # não tentou preparar ambiente de novo


def test_main_bootstraps_then_reexecs(monkeypatch):
    monkeypatch.setattr(launcher, "package_importable", lambda: False)
    monkeypatch.setattr(launcher, "ensure_env_file", lambda: None)
    monkeypatch.delenv(launcher._BOOTSTRAP_FLAG, raising=False)
    fake_py = Path("/venv/bin/python")
    monkeypatch.setattr(launcher, "ensure_environment", lambda: fake_py)
    seen = {}
    monkeypatch.setattr(launcher, "_reexec", lambda py, argv: seen.update(py=py, argv=argv) or 7)
    assert launcher.main(["scan", "x"]) == 7
    assert seen == {"py": fake_py, "argv": ["scan", "x"]}


def test_main_returns_error_when_environment_unavailable(monkeypatch):
    monkeypatch.setattr(launcher, "package_importable", lambda: False)
    monkeypatch.setattr(launcher, "ensure_env_file", lambda: None)
    monkeypatch.delenv(launcher._BOOTSTRAP_FLAG, raising=False)
    monkeypatch.setattr(launcher, "ensure_environment", lambda: None)
    assert launcher.main([]) == 1
