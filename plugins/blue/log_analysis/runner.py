"""Runner do log-analysis (Blue) — análise defensiva de logs, nativa em Python.

Diferente dos runners Red (que spawnam um binário externo), este é **puro
Python**: analisar log é passivo e não exige ferramenta externa. Por isso
sobrescreve ``available`` (sempre disponível) e ``scan`` (lê o arquivo/diretório
de log em vez de rodar subprocess). Os detectores vivem em ``parser.py``.

Alvo (``target``): caminho de um arquivo de log OU de um diretório (analisa cada
arquivo). Limite de tamanho por arquivo (anti-DoS de memória). Nunca executa
nada do log — só lê texto (§5, menor privilégio).
"""

from __future__ import annotations

from pathlib import Path

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import analyze_logs

_MAX_BYTES = 50 * 1024 * 1024  # 50 MiB por arquivo — evita esgotar memória


class LogAnalysisRunner(BaseToolPlugin):
    binary = "log-analysis"  # lógico; não é um executável no PATH
    name = "log-analysis"

    def available(self) -> bool:
        # Nativo em Python: sempre disponível (não depende de binário externo).
        return True

    def build_args(self, target: str, **_options) -> list[str]:  # pragma: no cover
        # Não usa subprocess; presente só para satisfazer o contrato abstrato.
        return []

    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        # Permite uso isolado/em teste: stdout = conteúdo do log.
        return analyze_logs(result.stdout, source=Path(target).name or target)

    def scan(self, target: str, **_options) -> list[Finding]:
        path = Path(target).expanduser()
        if not path.exists():
            raise FileNotFoundError(
                f"Log não encontrado: {target!r}. Informe um arquivo ou diretório de logs."
            )
        files = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
        findings: list[Finding] = []
        for fp in files:
            try:
                if fp.stat().st_size > _MAX_BYTES:
                    text = fp.open("r", errors="replace").read(_MAX_BYTES)
                else:
                    text = fp.read_text(errors="replace")
            except OSError:
                continue  # arquivo ilegível não derruba a análise dos demais
            findings.extend(analyze_logs(text, source=fp.name))
        findings.sort(key=lambda f: f.severity.rank, reverse=True)
        return findings
