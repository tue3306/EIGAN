"""Runner do whatweb — fingerprint de tecnologias/CMS de uma app web.

Roda após o httpx confirmar um serviço web vivo (cascata). Saída JSON estruturada
(``--log-json``) normalizada pelo ``parser.py``. Impacto ``active_safe``: só
requisições HTTP de identificação, sem exploração.
"""

from __future__ import annotations

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import parse


class WhatWebRunner(BaseToolPlugin):
    binary = "whatweb"
    name = "whatweb"

    def build_args(self, target: str, *, aggression: int = 3, **_) -> list[str]:
        # -a NÍVEL: 1=passivo (só a resposta base) … 3=agressivo padrão (algumas
        # sondas extras). --log-json=- envia o JSON para stdout (um token isolado).
        level = aggression if aggression in (1, 2, 3, 4) else 3
        return ["--quiet", "--no-errors", "--log-json=-", "-a", str(level), target]

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        return parse(result, target)
