"""Menu de produto — porta de entrada interativa do EIGAN (Missão 0).

`eigan` sem argumentos (ou `python3 eigan.py`) abre este **menu
numerado**: Novo Scan, Dashboard, Histórico, Configuração, Doctor, Atualizar
Ferramentas. É a camada de *produto* sobre a CLI — nenhuma regra de negócio nova
vive aqui: cada opção apenas orquestra casos de uso já existentes (wizard,
serve, doctor, feeds, store), de forma **testável** (``input_fn``/``echo``
injetáveis, como em :mod:`~eigan.cli.session`).

A experiência premium (TUI full-screen com Textual) fica em :mod:`.tui`; este
menu é o **fallback determinístico que funciona sempre** (só stdlib + click).
Ver ADR-0005.
"""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import sys
import threading
import time
import webbrowser
from typing import Callable

from .. import __version__
from ..engine.feeds import FeedCache
from ..findings.store import FindingStore
from ..security.onboarding import config_dir, terms_accepted
from . import doctor as doctor_mod

_REPORT_FORMATS = ("html", "pdf", "json", "csv", "sarif")
_REPORT_STYLES = ("technical", "executive")
_YES = {"s", "sim", "y", "yes"}


# --------------------------------------------------------------------------- #
# Apresentação (banner + menu). Box-drawing puro: alinha em qualquer terminal.
# --------------------------------------------------------------------------- #
def _boxed(lines: list[str], width: int = 58) -> str:
    inner = width - 2
    top = "╔" + "═" * inner + "╗"
    bottom = "╚" + "═" * inner + "╝"
    body = ["║" + (" " + ln).ljust(inner) + "║" for ln in lines]
    return "\n".join([top, *body, bottom])


def banner() -> str:
    return _boxed(
        [
            "EIGAN",
            "Plataforma de Operações de Segurança",
            "Red · Blue · Purple — uso autorizado apenas",
            f"v{__version__}",
        ]
    )


_ITEMS: tuple[tuple[str, str, str], ...] = (
    ("1", "Novo Scan", "assistente guiado: alvo → perspectiva → scan → relatório"),
    ("2", "Dashboard", "abre a interface web (API + dashboard) no navegador"),
    ("3", "Histórico", "scans anteriores, findings e geração de relatório"),
    ("4", "Configuração", "IA, banco de dados, feeds de risco e .env"),
    ("5", "Doctor", "diagnóstico do ambiente (Python, ferramentas, IA, feeds)"),
    ("6", "Atualizar Ferramentas", "feed de risco (CISA KEV) e checagem de ferramentas"),
    ("7", "Sair", ""),
)


def render_menu() -> str:
    lines = []
    for key, label, hint in _ITEMS:
        left = f"  {key}) {label}"
        lines.append(f"{left.ljust(28)}— {hint}" if hint else left)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Ações. Cada uma recebe (db, input_fn, echo) — nada de I/O global escondido.
# --------------------------------------------------------------------------- #
def action_new_scan(
    *, db: str, input_fn: Callable[[str], str] = input, echo: Callable = print
) -> None:
    """Delega ao wizard existente (alvo → perspectiva → consent inline → scan)."""
    from .wizard import run_wizard

    run_wizard(db)


def action_dashboard(
    *, db: str, input_fn: Callable[[str], str] = input, echo: Callable = print
) -> None:
    """Sobe a API + dashboard e abre o navegador. Ctrl-C retorna ao menu."""
    echo("Subindo o dashboard…  (Ctrl-C para voltar ao menu)")
    serve_app(host="127.0.0.1", port=8000, db=db, open_browser=True, echo=echo)


def action_history(
    *, db: str, input_fn: Callable[[str], str] = input, echo: Callable = print
) -> None:
    """Lista scans anteriores e permite ver findings / gerar relatório."""
    store = FindingStore(db)
    scans = store.list_scans()
    if not scans:
        echo("Nenhum scan registrado ainda. Use a opção 1 (Novo Scan).")
        return

    echo("\nScans recentes:")
    echo(f"  {'#':>4}  {'quando (UTC)':16}  {'perfil':12}  {'findings':>8}  {'pior':9}  alvos")
    for s in scans[:20]:
        findings = store.get_findings(s["id"])
        worst = max((f.severity for f in findings), key=lambda sev: sev.rank, default=None)
        worst_label = worst.value if worst else "—"
        targets = ", ".join(json.loads(s["targets"]))[:32]
        when = (s["started_at"] or "")[:16].replace("T", " ")
        echo(
            f"  {s['id']:>4}  {when:16}  {s['profile']:12}  "
            f"{len(findings):>8}  {worst_label:9}  {targets}"
        )

    choice = input_fn("\nVer detalhes de qual scan? (id, ou Enter para voltar): ").strip()
    if not choice:
        return
    if not choice.isdigit() or store.get_scan(int(choice)) is None:
        echo("Scan inexistente.")
        return
    _show_scan(store, int(choice), db=db, input_fn=input_fn, echo=echo)


def _show_scan(
    store: FindingStore, scan_id: int, *, db: str, input_fn: Callable[[str], str], echo: Callable
) -> None:
    findings = store.get_findings(scan_id)
    echo(f"\nScan #{scan_id}: {len(findings)} findings")
    for f in sorted(findings, key=lambda f: f.severity.rank, reverse=True)[:30]:
        risk = f"{f.risk.score:.0f}" if f.risk else "—"
        echo(f"  [{f.severity.value.upper():8}] risco {risk:>3}  {f.title}  ({f.affected_asset})")
    if not findings:
        return
    if input_fn("\nGerar relatório deste scan? [s/N]: ").strip().lower() in _YES:
        _generate_report(store, scan_id, input_fn=input_fn, echo=echo)


def _generate_report(
    store: FindingStore, scan_id: int, *, input_fn: Callable[[str], str], echo: Callable
) -> None:
    from .reporting import write_report
    from .session import feeds_meta

    fmt = (input_fn(f"Formato {list(_REPORT_FORMATS)} (html): ").strip() or "html").lower()
    if fmt not in _REPORT_FORMATS:
        echo("Formato desconhecido; usando html.")
        fmt = "html"
    style = (
        input_fn(f"Modelo {list(_REPORT_STYLES)} (executive): ").strip() or "executive"
    ).lower()
    if style not in _REPORT_STYLES:
        style = "executive"
    try:
        path, _ = write_report(
            store,
            scan_id,
            fmt=fmt,
            style=style,
            out=None,
            use_ai=False,
            feeds_meta=feeds_meta(FeedCache.load()),
        )
    except (ValueError, RuntimeError) as exc:  # ex.: WeasyPrint ausente para PDF
        echo(f"Não foi possível gerar {fmt}: {exc}")
        return
    echo(f"Relatório gerado: {path}")


def _upsert_env(values: dict[str, str], path: str = ".env") -> None:
    """Grava/atualiza chaves KEY=VALUE em ``.env`` (fora do git), preservando o
    resto. Nunca imprime o valor. Cria o arquivo se não existir."""
    lines: list[str] = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    seen: set[str] = set()
    for i, line in enumerate(lines):
        key = line.split("=", 1)[0].strip().lstrip("#").strip()
        if key in values:
            lines[i] = f"{key}={values[key]}"
            seen.add(key)
    for key, val in values.items():
        if key not in seen:
            lines.append(f"{key}={val}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)  # chaves são sensíveis: só o dono lê


def configure_ai_provider(
    *, input_fn: Callable[[str], str] = input, echo: Callable = print
) -> None:
    """Setup interativo do provedor de IA: escolher provedor → chave → modelo.

    Grava em ``.env`` (nunca ecoa a chave) e define ``EIGAN_AI_PROVIDER``. A IA é
    **obrigatória para escanear** (§3.4/ADR-0012): pular permite configurar
    depois, mas o scan é recusado enquanto não houver um provedor."""
    from ..ai.provider import list_providers

    specs = list_providers()
    echo("\nProvedores de IA disponíveis (multi-provedor — escolha um para escanear):")
    for i, s in enumerate(specs, start=1):
        echo(f"  {i:>2}. {s.label}")
        echo(f"      {s.scan_fit}")
    echo("   0. Pular (configurar depois — sem provedor, o scan é recusado)")
    raw = input_fn("\nEscolha o provedor [0]: ").strip() or "0"
    if not raw.isdigit() or int(raw) == 0 or int(raw) > len(specs):
        echo(
            "Provedor não configurado. Você pode ver dashboard, relatórios e "
            "histórico, mas o scan exige um provedor (configure em Configuração)."
        )
        return
    spec = specs[int(raw) - 1]
    values: dict[str, str] = {"EIGAN_AI_PROVIDER": spec.name}

    key_label = (
        "URL do host (ex.: http://localhost:11434)" if spec.name == "ollama" else "chave de API"
    )
    cred = input_fn(f"{spec.label} — {key_label}: ").strip()
    if not cred:
        echo("Sem credencial — nada foi alterado.")
        return
    values[spec.key_env] = cred

    model_hint = "deployment" if spec.name == "azure" else "modelo"
    default_note = f" (Enter usa o padrão {spec.default_model})" if spec.default_model else ""
    model = input_fn(f"{model_hint}{default_note}: ").strip()
    if model:
        values[spec.model_env] = model
    elif not spec.default_model:
        echo(f"Aviso: sem {spec.model_env}, o provedor fica inativo (não fabricamos id).")
    if spec.name == "azure":
        endpoint = input_fn("AZURE_OPENAI_ENDPOINT (https://<resource>.openai.azure.com): ").strip()
        api_ver = input_fn("AZURE_OPENAI_API_VERSION (confirme na doc): ").strip()
        if endpoint:
            values["AZURE_OPENAI_ENDPOINT"] = endpoint
        if api_ver:
            values["AZURE_OPENAI_API_VERSION"] = api_ver

    _upsert_env(values)
    for k, v in values.items():
        os.environ[k] = v  # aplica na sessão atual também
    echo(f"\n[✔] {spec.label} configurado e gravado em .env (fora do git, chmod 600).")
    echo("    A chave nunca é exibida. Rode 'Doctor' para confirmar o provedor ativo.")


def action_config(
    *, db: str, input_fn: Callable[[str], str] = input, echo: Callable = print
) -> None:
    """Mostra o estado da configuração e permite configurar a IA (sem editar YAML)."""
    from ..ai.provider import list_providers

    fc = FeedCache.load()
    ready = [s for s in list_providers() if s.configured()]
    env_state = "presente" if os.path.exists(".env") else "ausente (copie de .env.example)"
    ai_state = (
        f"{ready[0].label} · modelo={ready[0].model()}"
        if ready
        else "nenhum provedor — o scan será recusado (configure em Configuração)"
    )
    terms_state = "aceito" if terms_accepted() else "pendente (pedido no 1º scan)"
    kev_state = fc.kev_date() if fc.kev_available else "UNVERIFIED (opção 6 atualiza)"
    echo("\nConfiguração atual:")
    echo(f"  Banco de dados : {db}")
    echo(f"  .env           : {env_state}")
    echo(f"  IA             : {ai_state}")
    echo(f"  Termo de uso   : {terms_state}")
    echo(f"  Feed KEV       : {kev_state}")
    echo(f"  Diretório conf : {config_dir()}")
    if input_fn("\nConfigurar um provedor de IA agora? [s/N]: ").strip().lower() in _YES:
        configure_ai_provider(input_fn=input_fn, echo=echo)
    else:
        echo("Para ajustar manualmente: edite .env (chaves de IA / DATABASE_URL) ou config/*.yaml.")


def action_doctor(
    *, db: str, input_fn: Callable[[str], str] = input, echo: Callable = print
) -> None:
    """Diagnóstico do ambiente (reaproveita `eigan doctor`)."""
    report = doctor_mod.gather()
    doctor_mod.render(report, echo, _secho_adapter(echo))


def action_update_tools(
    *, db: str, input_fn: Callable[[str], str] = input, echo: Callable = print
) -> None:
    """Atualiza o feed de risco (CISA KEV) e lista ferramentas faltando."""
    echo("Atualizando feed CISA KEV (rede)…")
    fc = FeedCache.load()
    try:
        meta = fc.update_kev()
        echo(
            f"  KEV atualizado: {meta['count']} CVEs · "
            f"versão {meta.get('catalogVersion', '?')} · {meta.get('dateReleased', '?')}"
        )
    except Exception as exc:  # noqa: BLE001 — rede/parse: mensagem acionável, sem stack trace
        echo(f"  Falha ao atualizar KEV: {exc}")
        echo("  Sem o feed, KEV sai UNVERIFIED (nunca fabricado). Verifique a conexão.")

    echo("\nFerramentas de scan (plugins):")
    report = doctor_mod.gather()
    for t in report.tools:
        mark = "✔" if t.available else "✗"
        echo(f"  [{mark}] {t.name}")
        if not t.available and t.install_hint:
            echo(f"        instalar: {t.install_hint}")
    echo("\nDica: com Docker as ferramentas rodam em sandbox, sem instalar no host.")


def _secho_adapter(echo: Callable) -> Callable:
    """Adapta o ``echo`` do menu à assinatura ``secho(text, **style)`` do doctor."""

    def secho(text: str = "", **_kwargs: object) -> None:
        echo(text)

    return secho


# --------------------------------------------------------------------------- #
# Dashboard: sobe uvicorn e abre o navegador quando a porta responde.
# --------------------------------------------------------------------------- #
def _open_when_ready(host: str, port: int, url: str, timeout: float = 12.0) -> None:
    connect_host = "127.0.0.1" if host in ("", "0.0.0.0") else host

    def _wait_and_open() -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                if sock.connect_ex((connect_host, port)) == 0:
                    break
            time.sleep(0.25)
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001 — headless/sem navegador: a URL já foi impressa
            pass

    threading.Thread(target=_wait_and_open, daemon=True).start()


def serve_app(
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    db: str = "eigan.db",
    open_browser: bool = False,
    echo: Callable = print,
) -> None:
    """Sobe a API + dashboard (bloqueante). Compartilhado pelo menu e por `serve`."""
    os.environ["EIGAN_DB"] = db
    url = f"http://{host}:{port}"
    echo(f"EIGAN — dashboard: {url}   ·   API: {url}/api/v1   ·   docs: {url}/docs")
    if open_browser:
        echo("Abrindo o navegador assim que o servidor subir…")
        _open_when_ready(host, port, url)
    try:
        import uvicorn
    except ImportError:
        echo("uvicorn não está instalado. Rode: pip install -e .")
        return
    try:
        uvicorn.run("eigan.api.app:app", host=host, port=port, log_level="warning")
    except KeyboardInterrupt:
        echo("\nServidor encerrado.")


# --------------------------------------------------------------------------- #
# Loop principal + seleção de front-end (TUI Textual se houver; senão, menu).
# --------------------------------------------------------------------------- #
_DISPATCH: dict[str, Callable[..., None]] = {
    "1": action_new_scan,
    "2": action_dashboard,
    "3": action_history,
    "4": action_config,
    "5": action_doctor,
    "6": action_update_tools,
}
_QUIT = {"7", "0", "q", "sair", "quit", "exit"}


def run_menu(
    *, db: str = "eigan.db", input_fn: Callable[[str], str] = input, echo: Callable = print
) -> int:
    """Loop do menu numerado. Retorna 0 ao sair. Nunca vaza stack trace (§13)."""
    echo(banner())
    while True:
        echo("")
        echo(render_menu())
        try:
            choice = input_fn("\nEscolha uma opção [1-7]: ").strip().lower()
        except EOFError:
            echo("")
            return 0
        if choice in _QUIT:
            echo("Até logo.")
            return 0
        action = _DISPATCH.get(choice)
        if action is None:
            echo("Opção inválida — digite um número de 1 a 7.")
            continue
        try:
            action(db=db, input_fn=input_fn, echo=echo)
        except KeyboardInterrupt:
            echo("\n(interrompido — de volta ao menu)")
        except Exception as exc:  # noqa: BLE001 — menu resiliente: erro acionável, nunca stack trace
            echo(f"Erro: {exc}")


def _is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _textual_available() -> bool:
    return importlib.util.find_spec("textual") is not None


def run_frontend(db: str = "eigan.db") -> int:
    """Escolhe o front-end: TUI Textual (se instalada + TTY) ou o menu numerado."""
    if _is_interactive() and _textual_available():
        try:
            from .tui import run_tui
        except Exception:  # noqa: BLE001 — TUI é opcional: qualquer falha cai no menu
            return run_menu(db=db)
        return run_tui(db=db, fallback=lambda: run_menu(db=db))
    return run_menu(db=db)
