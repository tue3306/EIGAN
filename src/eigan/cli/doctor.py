"""`eigan doctor` — diagnóstico acionável do ambiente (§F).

Mostra versão do Python, ferramentas instaladas/faltando (com dica de instalação
de cada), se a IA está configurada (e que provedor usaria), disponibilidade do
Docker e estado dos feeds. Termina com um **veredito claro**.

A coleta (:func:`gather`) é pura e testável; a renderização recebe um ``echo``.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Callable

from ..engine.credentials import CredentialState
from ..engine.feeds import FeedCache
from ..engine.registry import PluginRegistry
from ..report.pdf_support import pdf_status


def _detect_ai() -> str | None:
    """Provedor de IA ativo, via o registro modular (ai/provider.py).

    Reflete a seleção real: provedor totalmente configurado (chave + modelo).
    Um provedor com chave mas SEM modelo aparece como pendente — sem fabricar id."""
    import os

    from ..ai.provider import current_tier, list_providers

    ready = [s for s in list_providers() if s.configured()]
    if ready:
        s = ready[0]
        return f"{s.label} · nível={current_tier()} · modelo={s.model()}"
    # chave presente (posta pelo USUÁRIO no env, não um default local) mas modelo
    # faltando? sinaliza o que falta. Providers com credencial-default (LM Studio)
    # que o usuário não tocou NÃO contam como "parcial".
    partial = [s for s in list_providers() if os.getenv(s.key_env) and not s.model()]
    if partial:
        s = partial[0]
        return f"{s.label} — falta definir {s.model_env} (sem fabricar id de modelo)"
    return None


def probe_ai(echo: Callable = print, secho: Callable = print) -> bool:
    """Testa de VERDADE se o provedor de IA ativo responde — faz uma chamada real.

    Diferente da linha 'IA' do relatório (que só reflete a config): aqui chamamos
    ``provider.probe()`` — Ollama checa ``/api/tags`` (servidor no ar + modelo
    puxado); a nuvem faz uma completude mínima. É o "certifique que a IA funciona"
    na prática (opt-in via ``doctor --probe-ai`` porque toca a rede/o modelo)."""
    from ..ai.provider import default_provider

    prov = default_provider()
    if prov is None:
        secho("\nIA (teste real): nenhum provedor configurado — nada a testar.", fg="yellow")
        return False
    secho("\nTestando o provedor de IA ativo (chamada real)…", fg="cyan")
    ok, detail = prov.probe()
    secho(
        f"  {'✔ IA respondeu' if ok else '✗ IA NÃO respondeu'} — {detail}",
        fg="green" if ok else "red",
    )
    if not ok:
        echo("  (config presente, mas a IA não respondeu — sem isso o scan cai no substrato.)")
    return ok


@dataclass
class ToolStatus:
    name: str
    capabilities: str
    available: bool
    degraded: bool
    install_hint: str
    roadmap: bool = False
    tool: str = ""  # binário subjacente (usado por `doctor --install`)
    impact_class: str = ""  # classe de destrutividade (Policy Engine, ADR-0011)
    licensing: str = "free"  # free | api_key | paid (ADR-0013)
    credentials: list[CredentialState] = field(default_factory=list)


@dataclass
class AgentStatus:
    """Agente cognitivo (ADR-0007): real (executa) ou scaffold (sugerido)."""

    name: str
    description: str
    built: bool
    capabilities: str


@dataclass
class DoctorReport:
    python_version: str
    python_ok: bool
    tools: list[ToolStatus] = field(default_factory=list)
    agents: list[AgentStatus] = field(default_factory=list)
    ai_provider: str | None = None
    docker: bool = False
    feeds_kev: str = ""
    feeds_epss: str = ""
    pdf_available: bool = False
    pdf_detail: str = ""
    seclists_root: str | None = None
    wordlist_by_profile: list[str] = field(default_factory=list)

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
        if self.ai_provider is None:
            # AI-native (§3.4/ADR-0012): sem provedor, nenhum scan roda.
            return "warn", (
                "Nenhum provedor de IA configurado — o EIGAN é um agente de IA e "
                "recusará o scan. Configure um (menu → Configuração, ou Ollama local)."
            )
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
            roadmap=s.metadata.roadmap,
            tool=s.metadata.tool,
            impact_class=s.metadata.impact_class.value,
            licensing=s.metadata.licensing.value,
            credentials=s.credential_states(),
        )
        for s in sorted(reg.all(), key=lambda s: s.name)
    ]
    from ..engine.cognitive import AgentRegistry

    agents = [
        AgentStatus(
            name=a.name,
            description=a.description,
            built=a.built,
            capabilities=", ".join(sorted(c.value for c in a.capabilities)),
        )
        for a in AgentRegistry.default().agents
    ]
    ai_provider = _detect_ai()
    fc = feeds if feeds is not None else FeedCache.load()
    pdf_ok, pdf_detail = pdf_status()
    from ..engine.wordlists import seclists_root, summary_by_profile

    return DoctorReport(
        python_version=platform.python_version(),
        python_ok=sys.version_info >= (3, 11),
        tools=tools,
        agents=agents,
        ai_provider=ai_provider,
        docker=shutil.which("docker") is not None,
        feeds_kev=fc.kev_date() if fc.kev_available else "",
        feeds_epss=fc.epss_date(),
        pdf_available=pdf_ok,
        pdf_detail=pdf_detail,
        seclists_root=seclists_root(),
        wordlist_by_profile=summary_by_profile("content"),
    )


def render(report: DoctorReport, echo, secho) -> None:
    secho("EIGAN — diagnóstico do ambiente\n", bold=True)
    ok = "✔"
    no = "✗"  # marcador de ausência

    py = ok if report.python_ok else no
    echo(f"[{py}] Python {report.python_version} (requer 3.11+)")

    echo("\nFerramentas (plugins) — [impacto: Policy Engine decide autônomo×HITL×recusa]:")
    _gated = {"exploit_validation", "state_changing"}
    for t in report.tools:
        mark = ok if t.available else no
        impact = f" ⟨{t.impact_class}⟩" if t.impact_class else ""
        gate = " ⚠ requer aprovação humana" if t.impact_class in _gated else ""
        lic = " 💳 PAGA/GUI — não automatizada" if t.licensing == "paid" else ""
        line = f"  [{mark}] {t.name:10}{impact} — {t.capabilities}{gate}{lic}"
        if t.degraded:
            line += "  (DEGRADADO)"
        echo(line)
        if not t.available and t.install_hint:
            echo(f"          instalar: {t.install_hint}")
        for cs in t.credentials:
            if cs.present:
                echo(f"          🔑 {cs.credential.label}: configurada")
            elif cs.missing_required:
                echo(
                    f"          🔑 {cs.credential.label}: FALTANDO (obrigatória) — "
                    f"{cs.credential.obtain_url or 'ver docs'}"
                )
            else:  # opcional ausente → cobertura parcial
                echo(
                    f"          🔑 {cs.credential.label}: ausente → resultado PARCIAL — "
                    f"obtenha em {cs.credential.obtain_url or 'ver docs'}"
                )

    if report.agents:
        echo("\nAgentes cognitivos (Planner goal-driven — ADR-0007):")
        for a in report.agents:
            mark = ok if a.built else "○"
            state = "real" if a.built else "scaffold (sugerido, não executado)"
            echo(f"  [{mark}] {a.name:16} — {state}")
            echo(f"          {a.description}")

    echo("\nIA (OBRIGATÓRIA — EIGAN é um agente de IA; ver docs/ai-providers.md):")
    if report.ai_provider:
        echo(f"  [{ok}] {report.ai_provider}")
    else:
        echo(f"  [{no}] nenhum provedor configurado — o scan será RECUSADO sem um.")
        echo("      configure: menu → Configuração (cole a chave), ou EIGAN_AI_PROVIDER + chave;")
        echo("      privacidade/offline sem custo: Ollama local.")

    echo("\nDocker (sandbox de ferramentas):")
    echo(
        f"  [{ok if report.docker else no}] docker "
        + ("disponível" if report.docker else "não encontrado (opcional)")
    )

    echo("\nRelatórios (PDF opcional; HTML sempre funciona):")
    echo(f"  [{ok if report.pdf_available else 'i'}] {report.pdf_detail}")

    echo("\nWordlists (descoberta de conteúdo — ffuf):")
    if report.seclists_root:
        echo(f"  [{ok}] SecLists: {report.seclists_root}")
    else:
        echo("  [i] SecLists não encontrado — usando a embutida (cobertura reduzida).")
        echo("      instale: sudo apt install seclists  (ou EIGAN_WORDLIST_DIR=/caminho/SecLists)")
    for line in report.wordlist_by_profile:
        echo(f"      {line}")

    echo("\nFeeds de risco (EPSS/KEV):")
    echo(f"  KEV : {report.feeds_kev or 'UNVERIFIED — rode `eigan feeds update`'}")
    echo(f"  EPSS: {report.feeds_epss or 'UNVERIFIED — enriquecido sob demanda no scan'}")

    level, message = report.verdict()
    color = {"ok": "green", "warn": "yellow", "error": "red"}[level]
    secho(f"\nVeredito: {message}", fg=color, bold=True)


# --------------------------------------------------------------------------- #
# `doctor --install` — provisão consent-gated das ferramentas REAIS ausentes.
#
# Estratégia (c) do ADR-0006. Anti-invenção (§3.1/§5): só geramos um comando
# executável quando ele é **padrão e verificável** (ex.: `nmap` no gerenciador de
# pacotes do SO). Para as ferramentas ProjectDiscovery — cujo `install_hint` é a
# URL oficial — NÃO fabricamos comando nem versão: apontamos a referência oficial
# (e Docker como sandbox). Nunca `shell=True`; sempre lista de argumentos (§5).
# --------------------------------------------------------------------------- #
_YES = {"s", "sim", "y", "yes"}
_PKG_MANAGERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("apt-get", ("apt-get", "install", "-y")),
    ("dnf", ("dnf", "install", "-y")),
    ("pacman", ("pacman", "-S", "--noconfirm")),
    ("apk", ("apk", "add")),
    ("brew", ("brew", "install")),
)


@dataclass
class InstallAction:
    tool: str
    method: str  # "package-manager" | "manual"
    reference: str
    command: list[str] | None = None  # executável só quando verificável
    note: str = ""


def _detect_pkg_manager() -> tuple[str, tuple[str, ...]] | None:
    for name, base in _PKG_MANAGERS:
        if shutil.which(name):
            return name, base
    return None


def _needs_sudo(pkg_manager: str) -> bool:
    if os.name != "posix" or pkg_manager == "brew":
        return False
    geteuid = getattr(os, "geteuid", None)
    return geteuid is None or geteuid() != 0


def plan_install(report: DoctorReport) -> list[InstallAction]:
    """Plano de instalação apenas para ferramentas **reais ausentes** (não-roadmap)."""
    actions: list[InstallAction] = []
    pm = _detect_pkg_manager()
    for t in report.tools:
        if t.roadmap or t.available or not t.tool:
            continue
        if t.tool == "nmap" and pm is not None:
            pm_name, base = pm
            command = [*base, "nmap"]
            if _needs_sudo(pm_name):
                command = ["sudo", *command]
            actions.append(
                InstallAction(
                    tool=t.tool,
                    method="package-manager",
                    reference=t.install_hint,
                    command=command,
                    note=f"via {pm_name} (pacote padrão do SO)",
                )
            )
        else:
            actions.append(
                InstallAction(
                    tool=t.tool,
                    method="manual",
                    reference=t.install_hint or "(sem referência oficial no metadata)",
                    command=None,
                    note="binário/imagem oficial (Docker é o caminho sandbox); versão # VERIFICAR",
                )
            )
    return actions


def _default_runner(command: list[str]) -> int:
    # Segurança §5: lista de argumentos, shell=False; herda stdio (sudo pode pedir senha).
    try:
        return subprocess.run(command, shell=False, check=False).returncode
    except OSError:
        return 127


def run_install(
    actions: list[InstallAction],
    *,
    assume_yes: bool = False,
    echo: Callable = print,
    confirm: Callable[[str], str] = input,
    runner: Callable[[list[str]], int] | None = None,
) -> int:
    """Executa o plano com **consentimento explícito** (§3.2). Retorna nº instalado.

    Lista exatamente o que vai rodar antes de pedir confirmação; o que é manual
    (fonte oficial) é só exibido, nunca executado por nós."""
    auto = [a for a in actions if a.command]
    manual = [a for a in actions if not a.command]

    if not actions:
        echo("Todas as ferramentas com runner real já estão presentes. Nada a instalar.")
        return 0

    echo("Plano de provisão (apenas ferramentas com runner real):\n")
    if auto:
        echo("Comandos que serão executados (mediante sua confirmação):")
        for a in auto:
            echo(f"  · {a.tool}: {' '.join(a.command or [])}   [{a.note}]")
    if manual:
        echo("\nInstalação manual — fonte oficial (não executo por você):")
        for a in manual:
            echo(f"  · {a.tool}: {a.reference}")
            if a.note:
                echo(f"      {a.note}")

    if not auto:
        echo("\nNada a executar automaticamente com segurança. Siga as referências oficiais")
        echo("acima ou use Docker (sandbox). Cada ferramenta ausente é apenas *pulada* no scan.")
        return 0

    if not assume_yes:
        answer = confirm("\nExecutar os comandos acima agora? [s/N]: ").strip().lower()
        if answer not in _YES:
            echo("Cancelado. Nada foi executado.")
            return 0

    run = runner or _default_runner
    installed = 0
    for a in auto:
        assert a.command is not None
        echo(f"\n→ {a.tool}: {' '.join(a.command)}")
        code = run(a.command)
        if code == 0:
            echo(f"  ✔ {a.tool} instalado.")
            installed += 1
        else:
            echo(f"  ✗ {a.tool}: falhou (código {code}). Verifique privilégios/conexão.")
    return installed
