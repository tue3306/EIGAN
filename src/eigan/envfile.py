"""Carregamento de ``.env`` sem dependência externa (§13 "baixa e roda").

O EIGAN grava chaves de IA em ``.env`` (fora do git). Faltava, porém, alguém
*ler* esse arquivo em runtime: num processo novo (``eigan serve``, a API, um scan
via CLI), ``os.getenv("OPENAI_API_KEY")`` vinha vazio mesmo com a chave no ``.env``
— e o gate AI-native recusava o scan por "falta de provedor". Este módulo corrige
isso com um parser mínimo (``KEY=VALUE``), sem puxar ``python-dotenv``.

Precedência 12-fator: o ambiente **real** vence o arquivo (``override=False``), para
que ``EIGAN_AI_PROVIDER=... eigan scan`` continue sobrepondo o ``.env``. É chamado
apenas pelos **entrypoints de runtime** (launcher, CLI, ``python -m eigan``) — nunca
em import de biblioteca, para não contaminar os testes com o ``.env`` do dev.
"""

from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: str | os.PathLike[str] = ".env", *, override: bool = False) -> bool:
    """Injeta as chaves de ``path`` em ``os.environ``. Retorna True se leu o arquivo.

    Ignora linhas em branco/comentário, aceita o prefixo ``export`` e remove aspas
    simples/duplas ao redor do valor. Nunca levanta: um ``.env`` ausente ou
    malformado apenas não define nada (o gate de IA continua dando o erro acionável).
    """
    p = Path(path)
    if not p.is_file():
        return False
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError:
        return False
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export ") :].strip()
        if not key:
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        if override or key not in os.environ:
            os.environ[key] = val
    return True
