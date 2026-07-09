"""Testes de onboarding (termo/escopo) e do diagnóstico `doctor`."""

from vulnforge.capability import Capability, Category
from vulnforge.cli import doctor
from vulnforge.engine.base import BaseToolPlugin
from vulnforge.engine.feeds import FeedCache
from vulnforge.engine.plugin import PluginMetadata, PluginSpec
from vulnforge.engine.registry import PluginRegistry
from vulnforge.perspective import Perspective
from vulnforge.security.onboarding import accept_terms, build_scope, terms_accepted


def test_accept_terms_writes_outside_repo_and_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNFORGE_CONFIG_DIR", str(tmp_path))
    assert not terms_accepted()
    assert accept_terms(assume_yes=True) is True
    assert terms_accepted() is True
    # segunda chamada não pede nada (idempotente).
    assert accept_terms(assume_yes=False) is True


def test_accept_terms_refused_returns_false(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNFORGE_CONFIG_DIR", str(tmp_path))
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
