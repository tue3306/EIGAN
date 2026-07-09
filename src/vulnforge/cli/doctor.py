"""`vulnforge doctor` — diagnóstico acionável do ambiente (§F).

Mostra versão do Python, ferramentas instaladas/faltando (com dica de instalação
de cada), se a IA está configurada (e que provedor usaria), disponibilidade do
Docker e estado dos feeds. Termina com um **veredito claro**.

A coleta (:func:`gather`) é pura e testável; a renderização recebe um ``echo``.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import dataclass, field

from ..engine.feeds import FeedCache
from ..engine.registry import PluginRegistry

_AI_ENV = {
    "ANTHROPIC_API_KEY": "Anthropic",
    "OPENAI_API_KEY": "OpenAI",
    "GOOGLE_API_KEY": "Google",
    "OLLAMA_HOST": "Ollama (local)",
}


@dataclass
class ToolStatus:
    name: str
    capabilities: str
    available: bool
    degraded: bool
    install_hint: str


@dataclass
class DoctorReport:
    python_version: str
    python_ok: bool
    tools: list[ToolStatus] = field(default_factory=list)
    ai_provider: str | None = None
    docker: bool = False
    feeds_kev: str = ""
    feeds_epss: str = ""

    @property
    def tools_available(self) -> int:
        return sum(1 for t in self.tools if t.available)

    @property
    def degraded_count(self) -> int:
        return sum(1 for t in self.tools if t.degraded)

    def verdict(self) -> tuple[str, str]:
        """Retorna (nível, mensagem): nível ∈ {ok, warn, error}."""
        if not self.python_ok:
            return "error", f"Python 3.11+ é requerido (encontrado {self.python_version})."
        if self.tools_available == 0:
            return "warn", (
                "Nenhuma ferramenta externa disponível. Instale ao menos uma "
                "(ex.: nmap) ou use o modo Docker — o engine roda o que houver."
            )
        return "ok", (
            f"{self.tools_available}/{len(self.tools)} ferramentas disponíveis. "
            "Pronto para escanear alvos autorizados."
        )


def gather(registry: PluginRegistry | None = None, feeds: FeedCache | None = None) -> DoctorReport:
    # NB: um registry vazio é falsy (tem __len__), então checagem explícita.
    reg = registry if registry is not None else PluginRegistry.discover()
    tools = [
        ToolStatus(
            name=s.name,
            capabilities=", ".join(c.value for c in s.metadata.capabilities),
            available=s.available(),
            degraded=s.degraded,
            install_hint=s.metadata.install_hint or s.metadata.version_source,
        )
        for s in sorted(reg.all(), key=lambda s: s.name)
    ]
    ai_provider = next((label for env, label in _AI_ENV.items() if os.getenv(env)), None)
    fc = feeds if feeds is not None else FeedCache.load()
    return DoctorReport(
        python_version=platform.python_version(),
        python_ok=sys.version_info >= (3, 11),
        tools=tools,
        ai_provider=ai_provider,
        docker=shutil.which("docker") is not None,
        feeds_kev=fc.kev_date() if fc.kev_available else "",
        feeds_epss=fc.epss_date(),
    )


def render(report: DoctorReport, echo, secho) -> None:
    secho("VulnForge — diagnóstico do ambiente\n", bold=True)
    ok = "✔"
    no = "✗"  # marcador de ausência

    py = ok if report.python_ok else no
    echo(f"[{py}] Python {report.python_version} (requer 3.11+)")

    echo("\nFerramentas (plugins):")
    for t in report.tools:
        mark = ok if t.available else no
        line = f"  [{mark}] {t.name:10} — {t.capabilities}"
        if t.degraded:
            line += "  (DEGRADADO)"
        echo(line)
        if not t.available and t.install_hint:
            echo(f"          instalar: {t.install_hint}")

    echo("\nIA (opcional):")
    if report.ai_provider:
        echo(
            f"  [{ok}] provedor detectado: {report.ai_provider} "
            "(modelo em config/ai.yaml — marcado VERIFICAR até confirmar)."
        )
    else:
        echo(
            "  [i] nenhuma chave detectada — o VulnForge funciona 100% sem IA "
            "(modo determinístico)."
        )

    echo("\nDocker (sandbox de ferramentas):")
    echo(
        f"  [{ok if report.docker else no}] docker "
        + ("disponível" if report.docker else "não encontrado (opcional)")
    )

    echo("\nFeeds de risco (EPSS/KEV):")
    echo(f"  KEV : {report.feeds_kev or 'UNVERIFIED — rode `vulnforge feeds update`'}")
    echo(f"  EPSS: {report.feeds_epss or 'UNVERIFIED — enriquecido sob demanda no scan'}")

    level, message = report.verdict()
    color = {"ok": "green", "warn": "yellow", "error": "red"}[level]
    secho(f"\nVeredito: {message}", fg=color, bold=True)
