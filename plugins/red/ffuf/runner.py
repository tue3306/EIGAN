"""Runner do ffuf — descoberta de conteúdo/diretórios ocultos (content discovery).

Faz fuzzing do caminho (``/FUZZ``) com uma wordlist resolvida por
``engine.wordlists`` (ADR-0019): **SecLists** quando houver, dimensionada pelo
perfil (quick→pequena, deep→grande); senão wordlist do SO; senão a **curada média
embutida**, avisando cobertura reduzida (§3.1). Saída JSON normalizada pelo parser.
"""

from __future__ import annotations

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.engine.wordlists import resolve
from eigan.findings.schema import Finding

from .parser import parse

# Códigos de status que contam como "achado" (existe algo ali).
_MATCH_CODES = "200,204,301,302,307,401,403,405,500"


class FfufRunner(BaseToolPlugin):
    binary = "ffuf"
    name = "ffuf"

    def build_args(
        self,
        target: str,
        *,
        rate_limit: int = 150,
        wordlist: str | None = None,
        profile: str = "standard",
        **_,
    ) -> list[str]:
        base = target.rstrip("/")
        url = base if "FUZZ" in base else f"{base}/FUZZ"
        wl = wordlist or resolve("content", profile).path
        return [
            "-u",
            url,
            "-w",
            wl,
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
