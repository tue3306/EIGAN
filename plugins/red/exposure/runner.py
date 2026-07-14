"""Runner do exposure prober (Red) — sonda HTTP nativa (stdlib urllib).

Nativo em Python (sem binário externo): faz GETs de identificação (impacto
active_safe — não explora, só lê recursos públicos). Para cada caminho sensível
confirma a exposição pela assinatura de conteúdo (parser.classify) e varre a
página base por segredos embutidos (parser.scan_secrets). Timeout e leitura
limitada por requisição (§5, robustez). SSL não verificado: é o ALVO sob teste,
não uma fonte confiável (contexto de pentest autorizado)."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding

from .parser import TOOL, classify, scan_secrets, sensitive_paths

_TIMEOUT = 8.0
_MAX_BYTES = 64 * 1024
_UA = "EIGAN-exposure/0.0.0 (authorized security assessment)"
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _base_url(target: str) -> str:
    t = target.strip().rstrip("/")
    if t.startswith(("http://", "https://")):
        return t
    return "https://" + t  # tenta https primeiro; runner faz fallback p/ http


def _get(url: str) -> tuple[int, str] | None:
    """GET seguro: (status, corpo) ou None (inacessível). Nunca levanta."""
    req = urllib.request.Request(url, headers={"User-Agent": _UA}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=_CTX) as resp:  # noqa: S310
            body = resp.read(_MAX_BYTES).decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(_MAX_BYTES).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            body = ""
        return exc.code, body
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, ValueError, OSError):
        return None


class ExposureRunner(BaseToolPlugin):
    binary = "exposure"  # lógico; sonda nativa, não é um executável no PATH
    name = TOOL

    def available(self) -> bool:
        return True  # stdlib urllib — sempre disponível

    def build_args(self, target: str, **_options) -> list[str]:  # pragma: no cover
        return []

    def parse(self, result: ToolResult, target: str) -> list[Finding]:  # pragma: no cover
        return []  # a sonda produz findings direto em scan(); parse não é usado

    def scan(self, target: str, **_options) -> list[Finding]:
        base = _base_url(target)
        findings: list[Finding] = []

        # 1) página base: fallback https→http; varre segredos embutidos.
        home = _get(base)
        if home is None and base.startswith("https://"):
            base = "http://" + base[len("https://") :]
            home = _get(base)
        if home is None:
            return []  # sem servidor web acessível — não sonda os caminhos (rápido)
        _status, body = home
        findings.extend(scan_secrets(base, body))

        # 2) caminhos sensíveis: 200 + assinatura de conteúdo = exposição confirmada.
        for path in sensitive_paths():
            got = _get(base + path)
            if got is None:
                continue
            status, body = got
            f = classify(path, base + path, status, body)
            if f is not None:
                findings.append(f)
                findings.extend(scan_secrets(base + path, body))  # segredos no arquivo vazado

        # dedup por fingerprint (mesmo segredo em base+arquivo) e ordena por severidade.
        uniq: dict[str, Finding] = {}
        for f in findings:
            uniq.setdefault(f.fingerprint, f)
        out = list(uniq.values())
        out.sort(key=lambda f: f.severity.rank, reverse=True)
        return out
