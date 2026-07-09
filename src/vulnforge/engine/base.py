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
from ..perspective import Perspective


class ToolNotAvailable(Exception):
    """Ferramenta externa não encontrada no PATH nem no sandbox."""


@dataclass
class ToolResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class BaseToolAdapter(ABC):
    """Porta única do domínio para qualquer ferramenta de scan.

    Metadados declarativos (perspectivas, credenciais, licença, uso comercial,
    fonte de versão) permitem que o orquestrador e o catálogo (config/tools.yaml)
    decidam ativação sem `if` espalhado. Licença/manutenção que você não
    confirmou entram como ``"verify"`` — nunca como fato (CLAUDE.md §5).
    """

    #: nome do binário no PATH
    binary: str = ""
    #: nome lógico da ferramenta (vai para `source_tool` do finding)
    name: str = ""
    #: timeout padrão em segundos
    default_timeout: int = 600
    #: perspectivas em que este adapter é aplicável
    supported_perspectives: tuple[Perspective, ...] = (
        Perspective.EXTERNAL,
        Perspective.INTERNAL,
    )
    #: precisa de credenciais (scan autenticado)?
    requires_credentials: bool = False
    #: fonte para resolver a versão (nunca fixar de memória — §5)
    version_source: str = "# VERIFICAR"
    #: licença declarada; "VERIFICAR" até confirmação na fonte oficial
    license: str = "VERIFICAR"
    #: uso comercial: "ok" | "verify" | "restricted"
    commercial_use: str = "verify"

    def runs_in(self, perspective: Perspective) -> bool:
        return perspective in self.supported_perspectives

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    @abstractmethod
    def build_args(self, target: str, **options) -> list[str]:
        """Monta a lista de argumentos (sem o binário). NUNCA retorne uma string
        única; cada token é um elemento da lista para evitar injeção de shell."""

    @abstractmethod
    def parse(self, result: ToolResult, target: str) -> list[Finding]:
        """Converte a saída bruta em findings normalizados."""

    def _run(self, args: list[str], timeout: int | None = None,
             stdin_data: str | None = None) -> ToolResult:
        """Executa a ferramenta com segurança: lista de argumentos, ``shell=False``
        e timeout obrigatório. ``stdin_data`` alimenta ferramentas que leem da
        entrada padrão (dnsx, httpx-PD).

        NOTA (sandbox): este é o modo "host". O caminho recomendado é rodar cada
        ferramenta em container efêmero (rede/escopo controlados); o adapter
        permanece o mesmo, trocando apenas o executor. Ver docker/.
        """
        if not self.available():
            raise ToolNotAvailable(
                f"'{self.binary}' não encontrado. Instale-o ou rode via sandbox Docker."
            )
        cmd = [self.binary, *args]
        try:
            proc = subprocess.run(
                cmd,
                input=stdin_data,
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

    #: alvo é passado via stdin em vez de argumento? (sobrescrito por adapters)
    target_via_stdin: bool = False

    def scan(self, target: str, *, timeout: int | None = None, **options) -> list[Finding]:
        args = self.build_args(target, **options)
        stdin_data = f"{target}\n" if self.target_via_stdin else None
        result = self._run(args, timeout=timeout, stdin_data=stdin_data)
        return self.parse(result, target)
