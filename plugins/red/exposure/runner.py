"""Runner do exposure prober (Red) — sonda HTTP nativa, blindada contra SSRF.

Nativo em Python (sem binário externo): faz GETs de identificação (impacto
active_safe — não explora, só lê recursos públicos). Para cada caminho sensível
confirma a exposição pela assinatura de conteúdo (parser.classify) e varre a
página base por segredos embutidos (parser.scan_secrets).

SEGURANÇA (ADR-0015): todo acesso HTTP passa por ``security.ssrf.safe_get``, que
NÃO segue redirect cegamente, resolve+tria+fixa o IP (anti-DNS-rebinding) e bloqueia
metadata de nuvem SEMPRE. ``allow_private`` vem da perspectiva: externo bloqueia
faixas internas; interno/unificado (assumed-breach) as permite. SSL não é verificado
para o ALVO (não é fonte confiável — contexto de pentest), mas isso nunca vira SSRF."""

from __future__ import annotations

from eigan.engine.base import BaseToolPlugin, ToolResult
from eigan.findings.schema import Finding
from eigan.security.ssrf import SsrfError, safe_get

from .parser import TOOL, classify, scan_secrets, sensitive_paths

_TIMEOUT = 8.0
_MAX_BYTES = 64 * 1024
_UA = "EIGAN-exposure/0.0.0 (authorized security assessment)"


def _base_url(target: str) -> str:
    t = target.strip().rstrip("/")
    if t.startswith(("http://", "https://")):
        return t
    return "https://" + t  # tenta https primeiro; runner faz fallback p/ http


def _get(url: str, *, allow_private: bool) -> tuple[int, str] | None:
    """GET blindado contra SSRF: (status, corpo) ou None (inacessível). Nunca levanta.

    Um destino de redirect/DNS que aponte para metadata/interno proibido é tratado
    como inacessível (None) — a sonda não vira pivô de ataque."""
    try:
        result = safe_get(
            url,
            allow_private=allow_private,
            timeout=_TIMEOUT,
            max_bytes=_MAX_BYTES,
            user_agent=_UA,
        )
    except SsrfError:
        return None  # metadata/interno bloqueado — não sonda
    if result is None:
        return None
    status, body, _final = result
    return status, body


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
        # allow_private pela perspectiva (ADR-0015): externo bloqueia faixas internas;
        # interno/unificado (assumed-breach) as permite. Default seguro: bloqueia.
        persp = str(_options.get("perspective", "external")).strip().lower()
        allow_private = persp in ("internal", "unified")

        base = _base_url(target)
        findings: list[Finding] = []

        # 1) página base: fallback https→http; varre segredos embutidos.
        home = _get(base, allow_private=allow_private)
        if home is None and base.startswith("https://"):
            base = "http://" + base[len("https://") :]
            home = _get(base, allow_private=allow_private)
        if home is None:
            return []  # sem servidor web acessível — não sonda os caminhos (rápido)
        _status, body = home
        findings.extend(scan_secrets(base, body))

        # 2) caminhos sensíveis: 200 + assinatura de conteúdo = exposição confirmada.
        for path in sensitive_paths():
            got = _get(base + path, allow_private=allow_private)
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
