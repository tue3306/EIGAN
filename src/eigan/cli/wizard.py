"""Wizard interativo — ``eigan`` sem argumentos (§F).

Guia o operador: o que escanear → perspectiva (com explicação) → perfil → usar
IA? (mostrando se há chave) → confirmação de autorização inline (no
:mod:`~eigan.cli.session`) → execução com progresso → oferta de PDF.
"""

from __future__ import annotations

import click

from ..ai.provider import list_providers
from ..perspective import Perspective
from ..findings.store import FindingStore
from .reporting import write_report
from .session import SessionAborted, execute_scan

_PROFILES = ["quick", "standard", "deep", "web-only", "network-only"]


def _ai_ready() -> bool:
    return any(s.configured() for s in list_providers())


def run_wizard(db: str = "eigan.db") -> int:
    click.secho("┌─ Assistente EIGAN ──────────────────────────────────┐", fg="cyan")
    click.secho("│ Scanner de vulnerabilidades para alvos AUTORIZADOS.      │", fg="cyan")
    click.secho("└─────────────────────────────────────────────────────────┘", fg="cyan")
    click.echo("Só escaneie o que você possui ou tem permissão escrita para testar.\n")

    target = click.prompt("O que deseja escanear? (host, IP ou URL)").strip()
    if not target:
        click.secho("Nenhum alvo informado.", fg="red")
        return 2

    # Onboarding da IA: se nenhum provedor está pronto, oferece configurar aqui
    # mesmo (inserir a API). É opcional — pular mantém o modo determinístico.
    if not _ai_ready() and click.confirm(
        "\nConfigurar um provedor de IA agora (Claude, GPT, Gemini, Groq, Ollama…)?",
        default=False,
    ):
        from .menu import configure_ai_provider

        configure_ai_provider(input_fn=lambda p: click.prompt(p, default="", show_default=False))

    click.echo("\nPerspectiva do scan:")
    click.echo("  external — visão de um atacante na internet (recusa alvos privados).")
    click.echo("  internal — visão de dentro da rede (recusa IP público).")
    persp = click.prompt(
        "Perspectiva",
        type=click.Choice([p.value for p in Perspective]),
        default=Perspective.EXTERNAL.value,
    )

    profile = click.prompt("\nPerfil de scan", type=click.Choice(_PROFILES), default="standard")

    ai_detected = _ai_ready()
    click.echo(
        f"\nIA: {'provedor configurado — explicações enriquecidas' if ai_detected else 'nenhum provedor — modo determinístico (100% funcional)'}."
    )
    online = click.confirm(
        "Enriquecer risco com EPSS online (FIRST.org) para os CVEs encontrados?", default=False
    )

    click.secho(f"\nIniciando scan de '{target}' [{persp}/{profile}]…", fg="green")
    try:
        outcome = execute_scan(
            targets=[target],
            perspective=Perspective(persp),
            profile=profile,
            scope_path=None,
            db=db,
            assume_yes=False,
            override_perspective=False,
            online_enrich=online,
            progress=lambda m: click.echo(f"  {m}"),
        )
    except SessionAborted as exc:
        click.secho(f"\nCancelado: {exc}", fg="yellow")
        return 1

    report = outcome.report
    click.secho(
        f"\nScan #{report.scan_id}: {len(report.findings)} findings ({report.perspective.value}).",
        fg="green",
    )
    for f in report.findings[:15]:
        risk = f"{f.risk.score:.0f}" if f.risk else "—"
        click.echo(
            f"  [{f.severity.value.upper():8}] risco {risk:>3}  {f.title}  ({f.affected_asset})"
        )
    if report.skipped_tools:
        click.secho(
            f"Ferramentas indisponíveis: {', '.join(report.skipped_tools)} (rode `eigan doctor`).",
            fg="yellow",
        )

    if report.scan_id is not None and click.confirm("\nGerar relatório?", default=True):
        fmt = click.prompt(
            "Formato", type=click.Choice(["pdf", "html", "json", "csv", "sarif"]), default="html"
        )
        style = click.prompt(
            "Modelo", type=click.Choice(["technical", "executive"]), default="executive"
        )
        try:
            path, ai_used = write_report(
                FindingStore(db),
                report.scan_id,
                fmt=fmt,
                style=style,
                out=None,
                use_ai=ai_detected,
                feeds_meta=outcome.feeds_meta,
            )
            click.secho(
                f"Relatório gerado: {path}  (IA: {'sim' if ai_used else 'não'})", fg="green"
            )
        except RuntimeError as exc:  # ex.: WeasyPrint ausente para PDF
            click.secho(f"Não foi possível gerar {fmt}: {exc}", fg="red")
            return 1
    return 0
