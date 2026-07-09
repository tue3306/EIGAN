"""Interface uniforme de adapter de ferramenta.

Todo scanner externo (nmap, nuclei, nikto, ...) é encapsulado por um
:class:`BaseToolAdapter` que: verifica disponibilidade, monta argumentos de
forma segura (lista, nunca string concatenada / nunca ``shell=True``), executa
com timeout, captura saída e faz o parse para o schema normalizado de finding.

Regras de segurança do produto (CLAUDE.md §3.4): sempre lista de argumentos,
nunca shell, timeout obrigatório, saída tratada.
"""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..findings.schema import Finding


class ToolNotAvailable(Exception):
    """Ferramenta externa não encontrada no PATH nem no sandbox."""


@dataclass
class ToolResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class BaseToolAdapter(ABC):
    #: nome do binário no PATH
    binary: str = ""
    #: nome lógico da ferramenta (vai para `source_tool` do finding)
    name: str = ""
    #: timeout padrão em segundos
    default_timeout: int = 600

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    @abstractmethod
    def build_args(self, target: str, **options) -> list[str]:
        """Monta a lista de argumentos (sem o binário). NUNCA retorne uma string
        única; cada token é um elemento da lista para evitar injeção de shell."""

    @abstractmethod
    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        """Converte a saída bruta em findings normalizados."""

    def _run(self, args: list[str], timeout: int | None = None) -> ToolResult:
        if not self.available():
            raise ToolNotAvailable(
                f"'{self.binary}' não encontrado. Instale-o ou rode via sandbox Docker."
            )
        cmd = [self.binary, *args]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.default_timeout,
                shell=False,  # explicitamente nunca shell
                check=False,
            )
            return ToolResult(proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as exc:
            return ToolResult(
                exit_code=124,
                stdout=exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                stderr="timeout",
                timed_out=True,
            )

    def scan(self, target: str, *, timeout: int | None = None, **options) -> list[Finding]:
        args = self.build_args(target, **options)
        result = self._run(args, timeout=timeout)
        return self.parse(result, target)
