"""Interface de linha de comando (headless/CI) + wizard interativo.

`vulnforge` sem subcomando abre o **wizard** (§F). Subcomandos: ``scan`` (zero-
config: external+standard por padrão), ``report`` (HTML/PDF/JSON/CSV/SARIF ×
técnico/executivo), ``serve`` (API+dashboard), ``doctor`` (diagnóstico) e
``feeds`` (atualização de EPSS/KEV).

Implementada com ``click``. Erros são **acionáveis** (dizem o que falta), nunca
stack trace cru.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from ..engine.feeds import FeedCache
from ..findings.schema import Severity
from ..findings.store import FindingStore
from ..perspective import Perspective
from ..security.scope import ScopeViolation
from . import doctor as doctor_mod
from .reporting import TOOL_VERSION, write_report
from .session import SessionAborted, execute_scan, feeds_meta
from .wizard import run_wizard


@click.group(invoke_without_command=True)
@click.version_option(TOOL_VERSION, prog_name="vulnforge")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """VulnForge — plataforma modular de operações de segurança (uso autorizado).

    Sem argumentos, abre o assistente interativo. Veja `vulnforge doctor` para
    checar o ambiente e `vulnforge scan ALVO` para um scan direto.
    """
    if ctx.invoked_subcommand is None:
        sys.exit(run_wizard())


@cli.command()
@click.argument("targets", nargs=-1)
@click.option("--target-list", type=click.Path(exists=True), help="Arquivo com um alvo por linha.")
@click.option("--perspective", type=click.Choice([p.value for p in Perspective]), default=None,
              help="external|internal. Padrão: external (ou o do scope.yaml).")
@click.option("--profile", default="standard", show_default=True)
@click.option("--scope", "scope_path", type=click.Path(exists=True), default=None,
              help="scope.yaml (trava dura, opcional). Sem ele, usa consent inline.")
@click.option("--db", default="vulnforge.db", show_default=True)
@click.option("--yes", is_flag=True, help="Consent + termo não-interativos (CI autorizado).")
@click.option("--online-enrich", is_flag=True, help="Buscar EPSS (FIRST.org) para os CVEs achados.")
@click.option("--override-perspective", is_flag=True,
              help="Libera a regra público×privado da perspectiva (auditado).")
@click.option("--fail-on", type=click.Choice([s.value for s in Severity]), default=None,
              help="Sai !=0 se houver finding >= esta severidade (gate de CI).")
def scan(targets, target_list, perspective, profile, scope_path, db, yes,
         online_enrich, override_perspective, fail_on):
    """Executa um scan contra ALVOS autorizados (ex.: `vulnforge scan example.com`)."""
    tlist = list(targets)
    if target_list:
        tlist += [ln.strip() for ln in Path(target_list).read_text().splitlines() if ln.strip()]
    if not tlist:
        raise click.UsageError("Informe ao menos um alvo (posicional) ou --target-list.")

    if override_perspective:
        click.secho("[AUDIT] override de perspectiva ATIVO", fg="yellow", err=True)

    try:
        outcome = execute_scan(
            targets=tlist, perspective=Perspective(perspective) if perspective else None,
            profile=profile, scope_path=scope_path, db=db, assume_yes=yes,
            override_perspective=override_perspective, online_enrich=online_enrich,
            progress=lambda m: click.echo(f"  {m}"),
        )
    except SessionAborted as exc:
        click.secho(f"Cancelado: {exc}", fg="yellow", err=True)
        sys.exit(1)
    except ScopeViolation as exc:
        click.secho(f"BLOQUEADO: {exc}", fg="red", err=True)
        sys.exit(2)

    report = outcome.report
    click.secho(f"\nScan #{report.scan_id} [{report.perspective.value}]: "
                f"{len(report.findings)} findings", fg="green")
    for f in report.findings:
        risk = f"{f.risk.score:.0f}" if f.risk else "—"
        click.echo(f"  [{f.severity.value.upper():8}] risco {risk:>3}  {f.title}  ({f.affected_asset})")
    if report.skipped_tools:
        click.secho(f"Ferramentas indisponíveis: {', '.join(report.skipped_tools)} "
                    "(rode `vulnforge doctor`).", fg="yellow")

    if fail_on:
        threshold = Severity(fail_on).rank
        worst = max((f.severity.rank for f in report.findings), default=-1)
        if worst >= threshold:
            click.secho(f"Gate CI: finding >= {fail_on} encontrado.", fg="red", err=True)
            sys.exit(1)


@cli.command()
@click.option("--scan", "scan_id", required=True, type=int)
@click.option("--db", default="vulnforge.db", show_default=True)
@click.option("--format", "fmt", type=click.Choice(["pdf", "html", "json", "csv", "sarif"]),
              default="html", show_default=True)
@click.option("--style", type=click.Choice(["technical", "executive"]), default="technical",
              show_default=True)
@click.option("--out", default=None)
@click.option("--ai/--no-ai", default=False, help="Enriquecer narrativa com IA (se houver chave).")
def report(scan_id, db, fmt, style, out, ai):
    """Gera relatório de um scan em HTML/PDF/JSON/CSV/SARIF (técnico ou executivo)."""
    store = FindingStore(db)
    fmeta = feeds_meta(FeedCache.load())
    try:
        path, ai_used = write_report(store, scan_id, fmt=fmt, style=style, out=out,
                                     use_ai=ai, feeds_meta=fmeta)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    except RuntimeError as exc:  # ex.: WeasyPrint ausente
        click.secho(f"Erro ao gerar {fmt}: {exc}", fg="red", err=True)
        sys.exit(1)
    click.secho(f"Relatório gerado: {path}  (IA: {'sim' if ai_used else 'não'})", fg="green")


@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8000, type=int, show_default=True)
@click.option("--db", default="vulnforge.db", show_default=True)
def serve(host, port, db):
    """Sobe a API + dashboard e imprime a URL."""
    import os

    import uvicorn
    os.environ["VULNFORGE_DB"] = db
    url = f"http://{host}:{port}"
    click.secho(f"VulnForge — dashboard em {url}  ·  API em {url}/api/v1  ·  docs em {url}/docs",
                fg="green")
    uvicorn.run("vulnforge.api.app:app", host=host, port=port)


@cli.command()
def doctor():
    """Diagnostica o ambiente (Python, ferramentas, IA, Docker, feeds)."""
    report_ = doctor_mod.gather()
    doctor_mod.render(report_, click.echo, click.secho)
    level, _ = report_.verdict()
    sys.exit(0 if level != "error" else 1)


@cli.group()
def feeds():
    """Feeds de risco (EPSS/KEV) — fonte oficial, com cache (ADR-0002)."""


@feeds.command("update")
def feeds_update():
    """Atualiza o catálogo CISA KEV (rede). EPSS é enriquecido sob demanda no scan."""
    fc = FeedCache.load()
    click.echo("Baixando CISA KEV…")
    try:
        meta = fc.update_kev()
    except Exception as exc:  # noqa: BLE001 — rede/parse: mensagem acionável, sem stack trace
        click.secho(f"Falha ao atualizar KEV: {exc}\n"
                    "Verifique a conexão; sem o feed, KEV sai UNVERIFIED (não fabricado).",
                    fg="red", err=True)
        sys.exit(1)
    click.secho(f"KEV atualizado: {meta['count']} CVEs · versão {meta.get('catalogVersion','?')} "
                f"· {meta.get('dateReleased','?')}", fg="green")
    click.echo(f"Cache: {fc.cache_dir}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
