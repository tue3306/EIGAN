"""Wizard interativo — ``eigan`` sem argumentos (§F).

Guia o operador: o que escanear → perspectiva → perfil → usar IA? → confirmação
de autorização inline (no :mod:`~eigan.cli.session`) → execução com progresso →
**resumo por severidade** → oferta de relatório → oferta de abrir o **dashboard
direto no scan** (deep-link ``#/scan/<id>``). A moldura vem de :mod:`.ui`.
"""

from __future__ import annotations

import click

from ..ai.provider import list_providers
from ..findings.schema import Finding, Severity
from ..perspective import Perspective
from ..findings.store import FindingStore
from .reporting import write_report
from .session import SessionAborted, execute_scan
from .ui import boxed, rule

_PROFILES = ["quick", "standard", "deep", "web-only", "network-only"]

# Severidade → (rótulo PT, cor click), da mais grave para a menos grave. Guia o
# resumo pós-scan (a "cara" do risco encontrado).
_SEV_DISPLAY: tuple[tuple[Severity, str, str], ...] = (
    (Severity.CRITICAL, "CRÍTICA", "red"),
    (Severity.HIGH, "ALTA", "bright_red"),
    (Severity.MEDIUM, "MÉDIA", "yellow"),
    (Severity.LOW, "BAIXA", "cyan"),
    (Severity.INFO, "INFO", "bright_black"),
)


def _ai_ready() -> bool:
    return any(s.configured() for s in list_providers())


def _count_by_severity(findings: list[Finding]) -> dict[Severity, int]:
    """Contagem de findings por severidade (base do resumo pós-scan)."""
    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] += 1
    return counts


def _severity_bar(counts: dict[Severity, int]) -> str:
    """Linha colorida ``CRÍTICA n   ALTA n   …`` — o retrato do risco encontrado."""
    parts = [
        click.style(f"{label} {counts[sev]}", fg=color, bold=counts[sev] > 0)
        for sev, label, color in _SEV_DISPLAY
    ]
    return "  " + "   ".join(parts)


def _print_results(report) -> None:
    """Resumo pós-scan: moldura + contagem por severidade + top findings por risco."""
    findings = report.findings
    total = len(findings)
    click.echo()
    click.secho(
        boxed(
            [
                f"Scan #{report.scan_id} concluído — {total} finding(s)",
                f"Perspectiva: {report.perspective.value}",
            ]
        ),
        fg="green",
    )
    click.echo(_severity_bar(_count_by_severity(findings)))

    # Validação (§16): quantas findings foram validadas/corroboradas + confiança.
    if findings:
        from ..analysis.validation import Validator

        vs = Validator().summarize(findings)
        conf = "  ".join(f"{k}:{n}" for k, n in sorted(vs.by_confidence.items()))
        click.secho(f"Validação: {vs.validated}/{vs.total} validadas · {conf}", fg="cyan")

    # Custo de IA (§22): tokens que a IA gastou comandando o scan.
    usage = getattr(report, "token_usage", None)
    if getattr(report, "ai_calls", 0) and usage is not None:
        click.secho(
            f"IA: {report.ai_calls} chamada(s) · {usage.total_tokens} tokens "
            f"({usage.prompt_tokens} in / {usage.completion_tokens} out)",
            fg="bright_black",
        )

    # Mais perigosos primeiro (risco, depois severidade) — a cara do ataque.
    top = sorted(
        findings,
        key=lambda f: (f.risk.score if f.risk else 0.0, f.severity.rank),
        reverse=True,
    )[:15]
    if top:
        click.echo()
        for f in top:
            risk = f"{f.risk.score:.0f}" if f.risk else "—"
            click.echo(
                f"  [{f.severity.value.upper():8}] risco {risk:>3}  {f.title}  "
                f"({f.affected_asset})  «{f.confidence.value}»"
            )
        if total > len(top):
            click.secho(
                f"  … e mais {total - len(top)} (veja no relatório ou no dashboard).",
                fg="bright_black",
            )
    if report.skipped_tools:
        click.secho(
            f"\nFerramentas indisponíveis: {', '.join(report.skipped_tools)} "
            "(rode `eigan doctor`).",
            fg="yellow",
        )


def _offer_report(report, *, db: str, ai_detected: bool, feeds_meta: dict) -> None:
    """Oferta de relatório (não fatal: falha de formato não derruba o fluxo)."""
    if report.scan_id is None or not click.confirm("\nGerar relatório?", default=True):
        return
    fmt = click.prompt(
        "Formato",
        type=click.Choice(["pdf", "html", "md", "json", "csv", "sarif"]),
        default="html",
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
            feeds_meta=feeds_meta,
        )
        click.secho(f"Relatório gerado: {path}  (IA: {'sim' if ai_used else 'não'})", fg="green")
    except RuntimeError as exc:  # ex.: WeasyPrint ausente para PDF
        click.secho(f"Não foi possível gerar {fmt}: {exc}", fg="red")


def _offer_dashboard(report, *, db: str) -> None:
    """Abre o dashboard direto no scan recém-concluído (deep-link ``#/scan/<id>``).

    Fechava aqui uma lacuna de UX: antes o wizard voltava ao menu sem oferecer a
    visualização web do que acabou de rodar.
    """
    if report.scan_id is None:
        return
    if not click.confirm("\nAbrir o dashboard agora para explorar este scan?", default=True):
        click.secho(
            f"Quando quiser: menu → Dashboard (ou `eigan serve`) e abra #/scan/{report.scan_id}.",
            fg="bright_black",
        )
        return
    from .menu import serve_app  # lazy: evita ciclo de import menu↔wizard

    click.secho("\nSubindo o dashboard…  (Ctrl-C encerra e volta ao menu)", fg="cyan")
    serve_app(db=db, open_browser=True, open_path=f"/#/scan/{report.scan_id}", echo=click.echo)


def run_wizard(db: str = "eigan.db") -> int:
    click.secho(
        boxed(
            [
                "Assistente EIGAN — Novo Scan",
                "Red · Blue · Purple — uso autorizado apenas",
                "Escaneie só o que você possui ou tem permissão escrita.",
            ]
        ),
        fg="cyan",
    )
    click.echo()

    target = click.prompt("O que deseja escanear? (host, IP ou URL)").strip()
    if not target:
        click.secho("Nenhum alvo informado.", fg="red")
        return 2

    # Gate AI-native (§3.4/ADR-0012): EIGAN é um agente de IA — sem provedor, não
    # há scan. Oferece configurar aqui mesmo (inserir a API); sem isso, aborta com
    # uma mensagem acionável (nunca stack trace).
    if not _ai_ready():
        click.secho(
            "\nEIGAN é um agente de IA: você precisa de um provedor para escanear.",
            fg="yellow",
        )
        if click.confirm(
            "Configurar agora (Claude, GPT, Gemini, Groq, Together, Azure ou Ollama local)?",
            default=True,
        ):
            from .menu import configure_ai_provider

            configure_ai_provider(
                input_fn=lambda p: click.prompt(p, default="", show_default=False)
            )
        if not _ai_ready():
            from ..ai.provider import _NO_PROVIDER_MSG

            click.secho("\n✗ Sem provedor de IA — scan cancelado.", fg="red", bold=True)
            click.echo(_NO_PROVIDER_MSG)
            return 3

    # Modo unificado: um só scan avalia alvos públicos E privados e documenta o que
    # encontrar — sem obrigar a escolher external/internal (esse guardrail estrito
    # segue em `eigan scan --perspective` para quem quer, mas não é imposto aqui).
    persp = Perspective.UNIFIED.value
    click.echo("\nModo: unificado — avalia público e privado; documenta IPs internos que achar.")

    profile = click.prompt("Perfil de scan", type=click.Choice(_PROFILES), default="standard")

    ai_detected = _ai_ready()  # True aqui: o gate acima recusa a ausência de provedor
    click.echo("\nIA: provedor configurado — enriquece a análise e as narrativas.")
    online = click.confirm(
        "Enriquecer risco com EPSS online (FIRST.org) para os CVEs encontrados?", default=False
    )

    click.echo()
    click.secho(rule(f"Scan: {target}  ·  {persp} / {profile}"), fg="green")
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
    _print_results(report)
    _offer_report(report, db=db, ai_detected=ai_detected, feeds_meta=outcome.feeds_meta)
    _offer_dashboard(report, db=db)
    return 0
