"""Onboarding de baixa fricção — sem remover a responsabilidade legal (§F).

Duas peças complementam o :mod:`~eigan.security.consent` (consent inline por
scan) e o :mod:`~eigan.security.scope` (trava dura por arquivo):

1. **Aceite de termo na 1ª execução**, gravado **fora do repositório**
   (``~/.config/eigan``), para não pedir de novo a cada scan.
2. **Escopo efêmero**: quando não há ``scope.yaml`` (opcional), constrói um escopo
   a partir dos alvos informados. A autorização continua sendo **afirmada** — via
   consent inline —, apenas não exige um arquivo (a trava dura por arquivo segue
   disponível para times/CI). As travas público×privado por perspectiva
   permanecem ativas.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from ..perspective import Perspective
from .scope import Scope

_TERMS_VERSION = "1"
_TERMS_TEXT = (
    "TERMO DE USO — EIGAN\n"
    "Esta ferramenta realiza scanning ativo de segurança. Você só pode escanear\n"
    "alvos que POSSUI ou para os quais tem PERMISSÃO ESCRITA de teste. Uso não\n"
    "autorizado é ilegal em diversas jurisdições e é de sua inteira responsabilidade.\n"
)


def config_dir() -> Path:
    env = os.getenv("EIGAN_CONFIG_DIR")
    return Path(env) if env else Path.home() / ".config" / "eigan"


def _accept_file() -> Path:
    return config_dir() / "accepted.json"


def terms_accepted() -> bool:
    return _accept_file().exists()


def accept_terms(*, assume_yes: bool = False, input_fn=input, echo=print) -> bool:
    """Mostra o termo curto na 1ª execução e grava o aceite fora do repo.

    ``assume_yes`` (``--yes`` em CI) registra o aceite sem interação. Retorna
    ``True`` se aceito (agora ou anteriormente)."""
    if terms_accepted():
        return True
    if not assume_yes:
        echo(_TERMS_TEXT)
        answer = input_fn("Você aceita e confirma que tem autorização? [yes]: ")
        if answer.strip().lower() not in {"yes", "s", "sim", "y"}:
            return False
    path = _accept_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "accepted_at": datetime.now(timezone.utc).isoformat(),
                "terms_version": _TERMS_VERSION,
            }
        )
    )
    return True


def build_scope(
    scope_path: str | Path | None, targets: list[str], perspective: Perspective
) -> Scope:
    """Resolve o escopo: do ``scope.yaml`` (trava dura opt-in) ou efêmero dos alvos.

    No modo efêmero (default do produto), ``authorized=True`` porque a autorização
    é afirmada inline (consent gate) e pelo termo de 1ª execução — nunca
    silenciosamente — e ``enforce_membership=False``: o alvo informado É o escopo,
    então não exigimos que ele conste de uma allowlist em arquivo (essa fricção
    chegava a barrar o próprio alvo quando digitado como URL). A trava dura por
    lista continua disponível para times/CI via ``--scope arquivo.yaml``."""
    if scope_path:
        return Scope.load(scope_path)
    return Scope(
        authorized=True,
        engagement=f"ad-hoc:{','.join(targets)[:60]}",
        hosts=list(targets),
        perspective=perspective,
        enforce_membership=False,
    )
