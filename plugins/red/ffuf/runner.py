"""Runner do ffuf — descoberta de conteúdo/diretórios ocultos (content discovery).

Faz fuzzing do caminho (``/FUZZ``) com uma wordlist. Usa a primeira wordlist do
sistema que existir (dirb/seclists) ou a wordlist embutida no plugin — assim
funciona out-of-the-box. Saída JSON (``-json``) normalizada pelo ``parser.py``.
"""

from __future__ import annotations

import os
from pathlib import Path

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse

# Wordlists do sistema, na ordem de preferência; a embutida é o fallback garantido.
_SYSTEM_WORDLISTS = (
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
)
_BUILTIN_WORDLIST = str(Path(__file__).with_name("wordlist.txt"))

# Códigos de status que contam como "achado" (existe algo ali).
_MATCH_CODES = "200,204,301,302,307,401,403,405,500"


def _wordlist() -> str:
    for w in _SYSTEM_WORDLISTS:
        if os.path.isfile(w):
            return w
    return _BUILTIN_WORDLIST


class FfufRunner(BaseToolPlugin):
    binary = "ffuf"
    name = "ffuf"

    def build_args(
        self, target: str, *, rate_limit: int = 150, wordlist: str | None = None, **_
    ) -> list[str]:
        base = target.rstrip("/")
        url = base if "FUZZ" in base else f"{base}/FUZZ"
        return [
            "-u",
            url,
            "-w",
            wordlist or _wordlist(),
            "-mc",
            _MATCH_CODES,
            "-t",
            "40",
            "-rate",
            str(int(rate_limit)),
            "-json",
            "-s",
            "-noninteractive",
        ]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
