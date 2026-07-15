"""Saúde de ferramenta — o contrato ``health_check`` do ToolAdapter (§12).

Uma :class:`Health` é a fotografia **verificável** do estado de um plugin/ferramenta:
está disponível? qual o status? qual o binário e onde ele está no PATH? Nada aqui é
fabricado (§2): a disponibilidade vem de ``shutil.which`` (fato), e **não** probamos
``<binário> --version`` às cegas (a flag varia por ferramenta) — a versão declarada
vive no ``metadata`` com ``# VERIFICAR`` e é resolvida por rotina própria, não aqui.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Health:
    """Estado de saúde de uma ferramenta (unidade do relatório de health §12/§19)."""

    name: str
    status: str  # ok | missing | roadmap | degraded
    available: bool
    binary: str = ""
    binary_path: str = ""  # caminho real no PATH (shutil.which) — verificável
    requires_credentials: bool = False
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "available": self.available,
            "binary": self.binary,
            "binary_path": self.binary_path,
            "requires_credentials": self.requires_credentials,
            "detail": self.detail,
        }
