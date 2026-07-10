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
from ..engine.cognitive import GoalKind
from .session import SessionAborted, execute_scan, feeds_meta, plan_scan


@click.group(invoke_without_command=True)
@click.version_option(TOOL_VERSION, prog_name="vulnforge")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """VulnForge — plataforma modular de operações de segurança (uso autorizado).

    Sem argumentos, abre o **menu interativo** (Novo Scan, Dashboard, Histórico,
    Configuração, Doctor, Atualizar Ferramentas). Veja `vulnforge doctor` para
    checar o ambiente e `vulnforge scan ALVO` para um scan direto (headless/CI).
    """
    if ctx.invoked_subcommand is None:
        from .menu import run_frontend

        sys.exit(run_frontend())


@cli.command()
@click.argument("targets", nargs=-1)
@click.option("--target-list", type=click.Path(exists=True), help="Arquivo com um alvo por linha.")
@click.option(
    "--perspective",
    type=click.Choice([p.value for p in Perspective]),
    default=None,
    help="external|internal. Padrão: external (ou o do scope.yaml).",
)
@click.option("--profile", default="standard", show_default=True)
@click.option(
    "--scope",
    "scope_path",
    type=click.Path(exists=True),
    default=None,
    help="scope.yaml (trava dura, opcional). Sem ele, usa consent inline.",
)
@click.option("--db", default="vulnforge.db", show_default=True)
@click.option("--yes", is_flag=True, help="Consent + termo não-interativos (CI autorizado).")
@click.option("--online-enrich", is_flag=True, help="Buscar EPSS (FIRST.org) para os CVEs achados.")
@click.option(
    "--override-perspective",
    is_flag=True,
    help="Libera a regra público×privado da perspectiva (auditado).",
)
@click.option(
    "--fail-on",
    type=click.Choice([s.value for s in Severity]),
    default=None,
    help="Sai !=0 se houver finding >= esta severidade (gate de CI).",
)
def scan(
    targets,
    target_list,
    perspective,
    profile,
    scope_path,
    db,
    yes,
    online_enrich,
    override_perspective,
    fail_on,
):
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
            targets=tlist,
            perspective=Perspective(perspective) if perspective else None,
            profile=profile,
            scope_path=scope_path,
            db=db,
            assume_yes=yes,
            override_perspective=override_perspective,
            online_enrich=online_enrich,
            progress=lambda m: click.echo(f"  {m}"),
        )
    except SessionAborted as exc:
        click.secho(f"Cancelado: {exc}", fg="yellow", err=True)
        sys.exit(1)
    except ScopeViolation as exc:
        click.secho(f"BLOQUEADO: {exc}", fg="red", err=True)
        sys.exit(2)

    report = outcome.report
    click.secho(
        f"\nScan #{report.scan_id} [{report.perspective.value}]: {len(report.findings)} findings",
        fg="green",
    )
    for f in report.findings:
        risk = f"{f.risk.score:.0f}" if f.risk else "—"
        click.echo(
            f"  [{f.severity.value.upper():8}] risco {risk:>3}  {f.title}  ({f.affected_asset})"
        )
    if report.skipped_tools:
        click.secho(
            f"Ferramentas indisponíveis: {', '.join(report.skipped_tools)} "
            "(rode `vulnforge doctor`).",
            fg="yellow",
        )

    if fail_on:
        threshold = Severity(fail_on).rank
        worst = max((f.severity.rank for f in report.findings), default=-1)
        if worst >= threshold:
            click.secho(f"Gate CI: finding >= {fail_on} encontrado.", fg="red", err=True)
            sys.exit(1)


@cli.command()
@click.argument("targets", nargs=-1)
@click.option(
    "--goal",
    default=GoalKind.ATTACK_SURFACE.value,
    show_default=True,
    help="Objetivo (aceita hífen ou underscore): " + " | ".join(g.value for g in GoalKind),
)
@click.option(
    "--perspective",
    type=click.Choice([p.value for p in Perspective]),
    default=None,
    help="external|internal. Padrão: o da perspectiva do objetivo.",
)
@click.option("--profile", default="standard", show_default=True)
@click.option("--scope", "scope_path", type=click.Path(exists=True), default=None)
@click.option("--db", default="vulnforge.db", show_default=True)
@click.option(
    "--dry-run/--execute",
    default=True,
    show_default=True,
    help="dry-run: só mostra o plano e a seleção justificada (não executa, sem consent).",
)
@click.option(
    "--ai/--no-ai", default=False, help="IA prioriza capacidades (fallback determinístico)."
)
@click.option("--yes", is_flag=True, help="Consent + termo não-interativos (execução autorizada).")
@click.option("--online-enrich", is_flag=True, help="Buscar EPSS (FIRST.org) na execução.")
@click.option("--override-perspective", is_flag=True, help="Libera público×privado (auditado).")
def plan(
    targets,
    goal,
    perspective,
    profile,
    scope_path,
    db,
    dry_run,
    ai,
    yes,
    online_enrich,
    override_perspective,
):
    """Núcleo cognitivo: dado um OBJETIVO, o Planner escolhe capacidades e o
    Selection Engine escolhe a ferramenta — tudo justificado (ADR-0007).

    Ex.: `vulnforge plan example.com --goal attack-surface` (dry-run, seguro).
    Adicione `--execute` para rodar de verdade (passa pelo consent gate).
    """
    tlist = list(targets)
    if not tlist:
        raise click.UsageError("Informe ao menos um alvo (posicional).")
    try:
        goal_kind = GoalKind.from_str(goal)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    try:
        outcome = plan_scan(
            goal_kind=goal_kind,
            targets=tlist,
            perspective=Perspective(perspective) if perspective else None,
            profile=profile,
            scope_path=scope_path,
            db=db,
            assume_yes=yes,
            override_perspective=override_perspective,
            online_enrich=online_enrich,
            dry_run=dry_run,
            use_ai=ai,
            echo=lambda m: click.echo(m),
        )
    except SessionAborted as exc:
        click.secho(f"Cancelado: {exc}", fg="yellow", err=True)
        sys.exit(1)
    except ScopeViolation as exc:
        click.secho(f"BLOQUEADO: {exc}", fg="red", err=True)
        sys.exit(2)

    mode = "PLANO (dry-run, nada executado)" if dry_run else "EXECUÇÃO"
    ai_txt = "IA" if outcome.ai_used else "determinístico"
    click.secho(
        f"\n{mode} · objetivo «{outcome.goal.kind.label}» "
        f"[{outcome.goal.perspective.value}] · planner={outcome.planner_name} ({ai_txt})",
        fg="cyan",
        bold=True,
    )
    for d in outcome.decisions:
        color = {
            "selected": "green",
            "executed": "green",
            "suggested": "yellow",
            "scaffold": "yellow",
            "skipped": "yellow",
            "failed": "red",
            "stop": "blue",
        }.get(d.action, None)
        click.secho(f"  {d.render()}", fg=color)

    if outcome.report is not None:
        r = outcome.report
        click.secho(
            f"\nScan #{r.scan_id}: {len(r.findings)} findings · parada: {r.stop_reason.value}",
            fg="green",
        )
    if outcome.suggestions:
        tools = ", ".join(s.tool for s in outcome.suggestions)
        click.secho(f"Sugeridas (não executadas): {tools}", fg="yellow")
    if dry_run:
        click.echo("\nPara executar de verdade: repita com --execute (exige autorização).")


@cli.command()
@click.option("--scan", "scan_id", required=True, type=int)
@click.option("--db", default="vulnforge.db", show_default=True)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["pdf", "html", "json", "csv", "sarif"]),
    default="html",
    show_default=True,
)
@click.option(
    "--style", type=click.Choice(["technical", "executive"]), default="technical", show_default=True
)
@click.option("--out", default=None)
@click.option("--ai/--no-ai", default=False, help="Enriquecer narrativa com IA (se houver chave).")
def report(scan_id, db, fmt, style, out, ai):
    """Gera relatório de um scan em HTML/PDF/JSON/CSV/SARIF (técnico ou executivo)."""
    store = FindingStore(db)
    fmeta = feeds_meta(FeedCache.load())
    try:
        path, ai_used = write_report(
            store, scan_id, fmt=fmt, style=style, out=out, use_ai=ai, feeds_meta=fmeta
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    except RuntimeError as exc:  # PDF indisponível → degrada para HTML (§13), sem stack trace
        if fmt == "pdf":
            click.secho(f"PDF indisponível: {exc}", fg="yellow", err=True)
            click.secho("Gerando HTML equivalente…", fg="yellow", err=True)
            path, ai_used = write_report(
                store, scan_id, fmt="html", style=style, out=None, use_ai=ai, feeds_meta=fmeta
            )
            click.secho(
                f"Relatório HTML gerado: {path}. Para PDF, habilite o WeasyPrint "
                "(rode `vulnforge doctor`).",
                fg="green",
            )
            return
        click.secho(f"Erro ao gerar {fmt}: {exc}", fg="red", err=True)
        sys.exit(1)
    click.secho(f"Relatório gerado: {path}  (IA: {'sim' if ai_used else 'não'})", fg="green")


@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8000, type=int, show_default=True)
@click.option("--db", default="vulnforge.db", show_default=True)
@click.option(
    "--open/--no-open",
    "open_browser",
    default=None,
    help="Abrir o navegador no dashboard (padrão: sim em terminal interativo).",
)
def serve(host, port, db, open_browser):
    """Sobe a API + dashboard, imprime a URL e (opcional) abre o navegador."""
    from .menu import serve_app

    if open_browser is None:
        open_browser = sys.stdout.isatty()
    serve_app(host=host, port=port, db=db, open_browser=open_browser, echo=click.echo)


@cli.command("menu")
@click.option("--db", default="vulnforge.db", show_default=True)
def menu_cmd(db):
    """Abre o menu interativo (porta de entrada de produto: TUI ou menu numerado)."""
    from .menu import run_frontend

    sys.exit(run_frontend(db))


@cli.command()
@click.option(
    "--install",
    "do_install",
    is_flag=True,
    help="Provisiona (com confirmação) as ferramentas com runner real que faltam.",
)
@click.option("--yes", is_flag=True, help="Confirma sem interação (automação autorizada).")
def doctor(do_install, yes):
    """Diagnostica o ambiente (Python, ferramentas, IA, Docker, PDF, feeds).

    Com --install, lista exatamente o que vai rodar e, após sua confirmação
    (consent gate), instala as ferramentas reais ausentes — nunca de fonte não
    oficial, nunca com shell.
    """
    report_ = doctor_mod.gather()
    doctor_mod.render(report_, click.echo, click.secho)
    if do_install:
        actions = doctor_mod.plan_install(report_)
        doctor_mod.run_install(actions, assume_yes=yes, echo=click.echo)
        return
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
        click.secho(
            f"Falha ao atualizar KEV: {exc}\n"
            "Verifique a conexão; sem o feed, KEV sai UNVERIFIED (não fabricado).",
            fg="red",
            err=True,
        )
        sys.exit(1)
    click.secho(
        f"KEV atualizado: {meta['count']} CVEs · versão {meta.get('catalogVersion', '?')} "
        f"· {meta.get('dateReleased', '?')}",
        fg="green",
    )
    click.echo(f"Cache: {fc.cache_dir}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
