"""Logging estruturado — configuração central e um logger com campos extras.

Um só ponto configura o logging de todo o EIGAN (chamado pelos entrypoints de
runtime). Dois formatos: **texto** legível (default, para o terminal) e **JSON**
(``EIGAN_LOG_FORMAT=json``) para ingestão em SIEM/observabilidade. Campos
estruturados (``scan_id``, ``tool``, ``target``, ``event``) vão em ``extra=`` e
aparecem no output — sem espalhar strings formatadas pelo código.

Nível por ``EIGAN_LOG_LEVEL`` (default INFO). Idempotente: não duplica handlers.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

_CONFIGURED = False
# Atributos padrão de um LogRecord — o que sobra são os campos estruturados (extra).
_STD = set(
    "name msg args levelname levelno pathname filename module exc_info exc_text stack_info "
    "lineno funcName created msecs relativeCreated thread threadName processName process "
    "taskName".split()
)


def _fields(record: logging.LogRecord) -> dict[str, Any]:
    return {k: v for k, v in record.__dict__.items() if k not in _STD and not k.startswith("_")}


class _TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%H:%M:%S")
        base = f"{ts} {record.levelname:<7} {record.name}: {record.getMessage()}"
        extra = _fields(record)
        if extra:
            base += "  " + " ".join(f"{k}={v}" for k, v in extra.items())
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            **_fields(record),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(*, level: str | None = None, fmt: str | None = None) -> None:
    """Configura o logger raiz ``eigan`` (idempotente). ``fmt`` = text | json."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    lvl = (level or os.getenv("EIGAN_LOG_LEVEL") or "INFO").upper()
    use_json = (fmt or os.getenv("EIGAN_LOG_FORMAT") or "text").lower() == "json"
    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter() if use_json else _TextFormatter())
    root = logging.getLogger("eigan")
    root.setLevel(getattr(logging, lvl, logging.INFO))
    root.handlers[:] = [handler]  # substitui (não acumula em reconfigs)
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Logger sob o namespace ``eigan.*`` (herda a config central)."""
    return logging.getLogger(name if name.startswith("eigan") else f"eigan.{name}")
