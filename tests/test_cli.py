"""Testes de onboarding (termo/escopo) e do diagnóstico `doctor`."""

from eigan.capability import Capability, Category
from eigan.cli import doctor
from eigan.engine.base import BaseToolPlugin
from eigan.engine.feeds import FeedCache
from eigan.engine.plugin import PluginMetadata, PluginSpec
from eigan.engine.registry import PluginRegistry
from eigan.perspective import Perspective
from eigan.security.onboarding import accept_terms, build_scope, terms_accepted


def test_accept_terms_writes_outside_repo_and_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("EIGAN_CONFIG_DIR", str(tmp_path))
    assert not terms_accepted()
    assert accept_terms(assume_yes=True) is True
    assert terms_accepted() is True
    # segunda chamada não pede nada (idempotente).
    assert accept_terms(assume_yes=False) is True


def test_accept_terms_refused_returns_false(tmp_path, monkeypatch):
    monkeypatch.setenv("EIGAN_CONFIG_DIR", str(tmp_path))
    ok = accept_terms(assume_yes=False, input_fn=lambda _p: "no", echo=lambda *_: None)
    assert ok is False and not terms_accepted()


def test_build_scope_ephemeral_authorizes_targets():
    scope = build_scope(None, ["example.com"], Perspective.EXTERNAL)
    assert scope.authorized is True
    assert scope.contains("example.com")
    assert scope.perspective is Perspective.EXTERNAL


def test_build_scope_from_file(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text("authorized: true\nengagement: t\nhosts: [10.0.0.5]\nperspective: internal\n")
    scope = build_scope(p, [], Perspective.EXTERNAL)
    assert scope.perspective is Perspective.INTERNAL
    assert scope.contains("10.0.0.5")


class _AvailablePlugin(BaseToolPlugin):
    binary = "nmap"

    def available(self):
        return True

    def build_args(self, target, **_):
        return [target]

    def parse(self, result, target):
        return []


def test_doctor_gather_and_verdict():
    spec = PluginSpec(
        metadata=PluginMetadata(
            name="nmap",
            category=Category.RED,
            capabilities=(Capability.PORT_DISCOVERY,),
            supported_perspectives=(Perspective.EXTERNAL,),
            tool="nmap",
        ),
        runner=_AvailablePlugin(),
    )
    reg = PluginRegistry([spec])
    rep = doctor.gather(registry=reg, feeds=FeedCache())
    assert rep.tools_available == 1
    level, _ = rep.verdict()
    assert level == "ok"


def test_doctor_verdict_warns_without_tools():
    reg = PluginRegistry([])
    rep = doctor.gather(registry=reg, feeds=FeedCache())
    assert rep.verdict()[0] == "warn"


# --------------------------------------------------------------------------- #
# `doctor --install` — plano/execução consent-gated (ADR-0006)
# --------------------------------------------------------------------------- #
def _tool(name, tool, *, available=False, roadmap=False, hint=""):
    return doctor.ToolStatus(
        name=name,
        capabilities="",
        available=available,
        degraded=False,
        install_hint=hint,
        roadmap=roadmap,
        tool=tool,
    )


def _report(tools):
    return doctor.DoctorReport(python_version="3.11.0", python_ok=True, tools=tools)


def test_plan_install_skips_available_and_roadmap():
    rep = _report([_tool("nmap", "nmap", available=True), _tool("x", "foo", roadmap=True)])
    assert doctor.plan_install(rep) == []


def test_plan_install_pd_tool_is_manual_no_fabricated_command(monkeypatch):
    monkeypatch.setattr(
        doctor, "_detect_pkg_manager", lambda: ("apt-get", ("apt-get", "install", "-y"))
    )
    rep = _report([_tool("httpx", "httpx", hint="https://exemplo/httpx#install")])
    plan = doctor.plan_install(rep)
    assert len(plan) == 1
    assert plan[0].method == "manual"
    assert plan[0].command is None  # anti-invenção: não fabrica comando p/ PD


def test_plan_install_nmap_uses_package_manager(monkeypatch):
    monkeypatch.setattr(
        doctor, "_detect_pkg_manager", lambda: ("apt-get", ("apt-get", "install", "-y"))
    )
    monkeypatch.setattr(doctor, "_needs_sudo", lambda pm: False)
    rep = _report([_tool("nmap", "nmap", hint="sudo apt install nmap")])
    plan = doctor.plan_install(rep)
    assert plan[0].command == ["apt-get", "install", "-y", "nmap"]


def test_run_install_requires_confirmation():
    action = doctor.InstallAction(
        "nmap", "package-manager", "", ["apt-get", "install", "-y", "nmap"]
    )
    ran: list[list[str]] = []
    n = doctor.run_install(
        [action],
        assume_yes=False,
        echo=lambda *_: None,
        confirm=lambda _p: "n",
        runner=lambda cmd: ran.append(cmd) or 0,
    )
    assert n == 0 and ran == []  # recusou → nada foi executado


def test_run_install_runs_auto_on_yes():
    action = doctor.InstallAction(
        "nmap", "package-manager", "", ["apt-get", "install", "-y", "nmap"]
    )
    ran: list[list[str]] = []
    n = doctor.run_install(
        [action], assume_yes=True, echo=lambda *_: None, runner=lambda cmd: ran.append(cmd) or 0
    )
    assert n == 1 and ran == [["apt-get", "install", "-y", "nmap"]]


def test_run_install_manual_only_executes_nothing():
    action = doctor.InstallAction("httpx", "manual", "https://exemplo/httpx", None)
    ran: list[list[str]] = []
    n = doctor.run_install(
        [action], assume_yes=True, echo=lambda *_: None, runner=lambda cmd: ran.append(cmd) or 0
    )
    assert n == 0 and ran == []


def test_pdf_status_returns_bool_and_detail():
    from eigan.report.pdf_support import pdf_status

    ok, detail = pdf_status()
    assert isinstance(ok, bool)
    assert isinstance(detail, str) and detail
