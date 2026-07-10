#!/usr/bin/env python3
"""VulnForge — launcher único (Missão 0: "baixa e roda").

    git clone …  &&  cd ScanVuln  &&  python3 vulnforge.py

Este arquivo usa **apenas a stdlib** e é o único ponto de entrada que um usuário
precisa conhecer. Num clone limpo, sem nada instalado, ele:

  1. cria um ambiente virtual em ``.venv``;
  2. instala o VulnForge e suas dependências (tentando o extra ``[tui]`` para a
     interface full-screen, com fallback para a base);
  3. gera ``.env`` a partir de ``.env.example``;
  4. reexecuta a si mesmo dentro do venv e abre o **menu interativo**.

Se o pacote já estiver importável (venv ativo, ``pip install -e .``, Docker…),
ele pula o bootstrap e inicia direto. Argumentos são repassados à CLI:

    python3 vulnforge.py                 # menu interativo (Novo Scan, Dashboard…)
    python3 vulnforge.py scan alvo.com   # scan direto (headless/CI)
    python3 vulnforge.py doctor          # diagnóstico do ambiente

Uso autorizado apenas: só escaneie alvos que você possui ou tem permissão
escrita para testar.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"
_BOOTSTRAP_FLAG = "VULNFORGE_BOOTSTRAPPED"
# Tenta a experiência premium (TUI Textual); se falhar, instala só a base.
_INSTALL_SPECS = (".[tui]", ".")


def _deshadow() -> None:
    """Impede que este script (``ROOT/vulnforge.py``) sombreie o pacote instalado
    ``vulnforge`` (mesmo nome). Remove o diretório do script de ``sys.path`` — o
    módulo já carregado como ``__main__`` continua válido. Idempotente."""
    root = str(ROOT)
    sys.path[:] = [p for p in sys.path if p not in ("", ".", root)]


def venv_python(venv_dir: Path = VENV_DIR) -> Path:
    """Caminho do interpretador dentro de um venv (POSIX/Windows)."""
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def package_importable() -> bool:
    """True se o **pacote** ``vulnforge`` (não este script) é importável agora."""
    import importlib.util

    try:
        # O submódulo evita casar com o script (que não é um pacote).
        return importlib.util.find_spec("vulnforge.cli.main") is not None
    except (ImportError, ValueError):
        return False


def ensure_env_file() -> None:
    """Autoconfig da 1ª execução: cria ``.env`` a partir de ``.env.example``."""
    env, example = ROOT / ".env", ROOT / ".env.example"
    if example.exists() and not env.exists():
        try:
            shutil.copyfile(example, env)
            print("· .env criado a partir de .env.example")
        except OSError as exc:
            print(f"· não foi possível criar .env: {exc}")


def create_venv() -> bool:
    print("· Criando ambiente virtual em .venv (primeira execução)…")
    try:
        import venv

        venv.EnvBuilder(with_pip=True, upgrade_deps=False).create(str(VENV_DIR))
        return True
    except Exception as exc:  # noqa: BLE001 — acionável (ex.: falta o módulo venv)
        print(f"  Falha ao criar o venv: {exc}")
        print("  Instale o módulo venv (Debian/Ubuntu/Kali): sudo apt install python3-venv")
        return False


def _venv_has_package(py: Path) -> bool:
    # `-I` isola o interpretador (ignora cwd e PYTHON*), evitando que o script
    # ROOT/vulnforge.py seja importado no lugar do pacote.
    result = subprocess.run(
        [str(py), "-I", "-c", "import vulnforge.cli.main"],
        capture_output=True,
    )
    return result.returncode == 0


def _pip_install(py: Path, spec: str) -> bool:
    result = subprocess.run([str(py), "-m", "pip", "install", "-q", "-e", spec], cwd=str(ROOT))
    return result.returncode == 0


def install_package(py: Path) -> bool:
    subprocess.run([str(py), "-m", "pip", "install", "-q", "--upgrade", "pip"], cwd=str(ROOT))
    print("· Instalando o VulnForge e dependências…")
    for spec in _INSTALL_SPECS:
        if _pip_install(py, spec):
            return True
        print(f"  ('{spec}' não instalou; tentando alternativa mais simples…)")
    print("  Falha ao instalar as dependências. Verifique a conexão e tente de novo.")
    return False


def ensure_environment() -> Path | None:
    """Garante um venv com o pacote instalado. Retorna o python do venv ou None."""
    py = venv_python()
    if not py.exists():
        if not create_venv():
            return None
        py = venv_python()
    if not _venv_has_package(py):
        if not install_package(py):
            return None
    return py


def run_app(argv: list[str]) -> int:
    """Entrega o controle à CLI do pacote instalado (menu quando sem argumentos)."""
    from vulnforge.cli.main import main as cli_main

    sys.argv = ["vulnforge", *argv]
    try:
        cli_main()
    except SystemExit as exc:  # click chama sys.exit; propaga o código
        return int(exc.code or 0)
    return 0


def _reexec(py: Path, argv: list[str]) -> int:
    env = {**os.environ, _BOOTSTRAP_FLAG: "1"}
    print("· Ambiente pronto — iniciando o VulnForge…\n")
    return subprocess.run([str(py), str(ROOT / "vulnforge.py"), *argv], env=env).returncode


def _fail_actionable() -> None:
    print("\nNão foi possível preparar o ambiente automaticamente. Faça manualmente:")
    print("  python3 -m venv .venv && . .venv/bin/activate")
    print("  pip install -e '.[tui]'")
    print("  vulnforge")


def main(argv: list[str]) -> int:
    _deshadow()
    ensure_env_file()

    if package_importable():
        return run_app(argv)

    # Pacote não importável: preparamos um venv e reexecutamos dentro dele.
    if os.environ.get(_BOOTSTRAP_FLAG):
        # Já tentamos preparar+reexecutar e ainda assim não importa: erro real.
        _fail_actionable()
        return 1

    py = ensure_environment()
    if py is None:
        return 1
    return _reexec(py, argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
