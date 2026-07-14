"""Testes do parser mínimo de ``.env`` (``eigan.envfile``).

Trava o contrato de onboarding (§13): ler chaves gravadas em ``.env`` num processo
novo, com precedência 12-fator (o ambiente real vence o arquivo), sem depender de
``python-dotenv`` e sem nunca levantar exceção.
"""

from __future__ import annotations

from eigan.envfile import load_dotenv


def _write(tmp_path, body: str):
    p = tmp_path / ".env"
    p.write_text(body, encoding="utf-8")
    return p


def test_missing_file_returns_false(tmp_path, monkeypatch):
    monkeypatch.delenv("EIGAN_UNSET_XYZ", raising=False)
    assert load_dotenv(tmp_path / "nao-existe.env") is False


def test_parses_key_value(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    p = _write(tmp_path, "OPENAI_API_KEY=sk-abc123\n")
    assert load_dotenv(p) is True
    import os

    assert os.environ["OPENAI_API_KEY"] == "sk-abc123"


def test_ignores_comments_blanks_and_malformed(tmp_path, monkeypatch):
    monkeypatch.delenv("FOO", raising=False)
    p = _write(tmp_path, "\n# comentário\n   \nlinha-sem-igual\nFOO=bar\n")
    assert load_dotenv(p) is True
    import os

    assert os.environ["FOO"] == "bar"


def test_strips_surrounding_quotes(tmp_path, monkeypatch):
    monkeypatch.delenv("Q1", raising=False)
    monkeypatch.delenv("Q2", raising=False)
    p = _write(tmp_path, "Q1=\"dupla\"\nQ2='simples'\n")
    load_dotenv(p)
    import os

    assert os.environ["Q1"] == "dupla"
    assert os.environ["Q2"] == "simples"


def test_export_prefix_is_stripped(tmp_path, monkeypatch):
    monkeypatch.delenv("EXPORTED", raising=False)
    p = _write(tmp_path, "export EXPORTED=1\n")
    load_dotenv(p)
    import os

    assert os.environ["EXPORTED"] == "1"


def test_real_env_wins_by_default(tmp_path, monkeypatch):
    # Precedência 12-fator: ambiente real vence o arquivo (override=False).
    monkeypatch.setenv("PROVIDER_X", "do-ambiente")
    p = _write(tmp_path, "PROVIDER_X=do-arquivo\n")
    load_dotenv(p)
    import os

    assert os.environ["PROVIDER_X"] == "do-ambiente"


def test_override_true_lets_file_win(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVIDER_Y", "do-ambiente")
    p = _write(tmp_path, "PROVIDER_Y=do-arquivo\n")
    load_dotenv(p, override=True)
    import os

    assert os.environ["PROVIDER_Y"] == "do-arquivo"


def test_never_raises_on_directory(tmp_path):
    # Um caminho que não é arquivo regular não deve levantar — só retorna False.
    assert load_dotenv(tmp_path) is False


def test_empty_key_is_skipped(tmp_path, monkeypatch):
    monkeypatch.delenv("VALIDA", raising=False)
    p = _write(tmp_path, "=sem-chave\nVALIDA=ok\n")
    load_dotenv(p)
    import os

    assert os.environ["VALIDA"] == "ok"


def test_unreadable_file_returns_false(tmp_path, monkeypatch):
    # Erro de I/O na leitura é engolido (retorna False), nunca propaga.
    p = _write(tmp_path, "K=V\n")

    def _boom(*_a, **_k):
        raise OSError("permissão negada")

    monkeypatch.setattr("pathlib.Path.read_text", _boom)
    assert load_dotenv(p) is False
