"""Interface de linha de comando (headless/CI).

Implementada com ``click`` (Typer é o alvo do roadmap; click garante execução
sem deps adicionais). Suporta o gate de escopo, consent gate, `--no-ai` e o
`--fail-on` para pipelines de CI (sai != 0 acima do limiar).
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from ..ai.provider import Enricher, default_provider
from ..engine.orchestrator import Orchestrator
from ..findings.schema import Severity
from ..findings.store import FindingStore
from ..knowledge.loader import KnowledgeBase
from ..perspective import Perspective
from ..report.deterministic import ReportGenerator
from ..security.consent import ConsentGate
from ..security.scope import Scope, ScopeViolation

_KB_DIR = Path(__file__).resolve().parents[3] / "knowledge" / "skills"


def _kb() -> KnowledgeBase:
    return KnowledgeBase(_KB_DIR)


@click.group()
@click.version_option("0.1.0", prog_name="vulnforge")
def cli() -> None:
    """VulnForge — plataforma de scanning e gestão de vulnerabilidades.

    Uso autorizado apenas. Requer scope.yaml com alvos que você tem permissão
    documentada para testar.
    """


@cli.command()
@click.option("--target", "targets", multiple=True, help="Alvo (repetível).")
@click.option("--target-list", type=click.Path(exists=True), help="Arquivo com um alvo por linha.")
@click.option("--profile", default="standard", show_default=True)
@click.option("--perspective", "perspective", type=click.Choice([p.value for p in Perspective]),
              default=None, help="external|internal. Sobrepõe o valor do scope.yaml.")
@click.option("--scope", "scope_path", required=True, type=click.Path(exists=True))
@click.option("--db", default="vulnforge.db", show_default=True)
@click.option("--no-ai", is_flag=True, help="Força modo determinístico.")
@click.option("--yes", is_flag=True, help="Consent gate não-interativo (CI autorizado).")
@click.option("--override-perspective", is_flag=True,
              help="Libera a regra público×privado da perspectiva (logado). Use com cautela.")
@click.option("--fail-on", type=click.Choice([s.value for s in Severity]), default=None,
              help="Sai com código !=0 se houver finding >= esta severidade.")
def scan(targets, target_list, profile, perspective, scope_path, db, no_ai, yes,
         override_perspective, fail_on):
    """Executa um scan contra alvos autorizados."""
    tlist = list(targets)
    if target_list:
        tlist += [ln.strip() for ln in Path(target_list).read_text().splitlines() if ln.strip()]
    if not tlist:
        raise click.UsageError("Informe --target ou --target-list.")

    scope = Scope.load(scope_path)
    persp = Perspective(perspective) if perspective else scope.perspective
    if override_perspective:
        click.secho(f"[AUDIT] override de perspectiva ATIVO (persp={persp.value})", fg="yellow", err=True)
    try:
        ConsentGate(scope.engagement, tlist).require(assume_yes=yes)
        store = FindingStore(db)
        orch = Orchestrator(store=store)
        report = orch.run(tlist, scope=scope, perspective=persp, profile=profile,
                          override_perspective=override_perspective,
                          progress=lambda m: click.echo(f"  {m}"))
    except ScopeViolation as exc:
        click.secho(f"BLOQUEADO: {exc}", fg="red", err=True)
        sys.exit(2)

    click.secho(f"\nScan #{report.scan_id} [{report.perspective.value}]: "
                f"{len(report.findings)} findings", fg="green")
    for f in report.findings:
        click.echo(f"  [{f.severity.value.upper():8}] {f.title}  ({f.affected_asset})")
    if report.skipped_tools:
        click.secho(f"Ferramentas indisponíveis: {', '.join(report.skipped_tools)}", fg="yellow")

    if fail_on:
        threshold = Severity(fail_on).rank
        worst = max((f.severity.rank for f in report.findings), default=-1)
        if worst >= threshold:
            click.secho(f"Gate CI: finding >= {fail_on} encontrado.", fg="red", err=True)
            sys.exit(1)


@cli.command()
@click.option("--scan", "scan_id", required=True, type=int)
@click.option("--db", default="vulnforge.db", show_default=True)
@click.option("--format", "fmt", type=click.Choice(["pdf", "html"]), default="pdf")
@click.option("--out", default=None)
@click.option("--ai/--no-ai", default=False, help="Enriquecer sumário com IA (se houver chave).")
def report(scan_id, db, fmt, out, ai):
    """Gera relatório PDF/HTML de um scan."""
    store = FindingStore(db)
    meta = store.get_scan(scan_id)
    if not meta:
        raise click.UsageError(f"Scan {scan_id} não encontrado.")
    findings = store.get_findings(scan_id)
    provider = default_provider() if ai else None
    enricher = Enricher(_kb(), provider=provider)
    gen = ReportGenerator(enricher)

    import json as _json
    targets = _json.loads(meta["targets"])
    out = out or f"report_scan_{scan_id}.{fmt}"
    if fmt == "html":
        Path(out).write_text(gen.render_html(findings, engagement=meta["engagement"], targets=targets))
    else:
        gen.render_pdf(findings, out, engagement=meta["engagement"], targets=targets)
    click.secho(f"Relatório gerado: {out}  (IA: {'sim' if enricher.ai_enabled else 'não'})", fg="green")


@cli.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8000, type=int)
def serve(host, port):
    """Sobe a API + dashboard."""
    import uvicorn
    uvicorn.run("vulnforge.api.app:app", host=host, port=port, factory=False)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
