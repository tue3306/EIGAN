"""Testes da gestão de credenciais de FERRAMENTA (ADR-0013).

Cobre o modelo declarativo (ToolCredential/Licensing), a resolução contra o
ambiente, o aviso de cobertura parcial (§3.1), o parse a partir do metadata real
(wpscan/subfinder/burp) e a geração do provider-config do subfinder.
"""

from __future__ import annotations

from eigan.engine.credentials import (
    CredentialState,
    Licensing,
    ToolCredential,
    coverage_warning,
    resolve_credentials,
)
from eigan.engine.registry import PluginRegistry


def _cred(env: str, required: bool = False, degrades: str = "x") -> ToolCredential:
    return ToolCredential(env=env, label=env, required=required, degrades=degrades)


def test_licensing_from_str():
    assert Licensing.from_str("paid") is Licensing.PAID
    assert Licensing.from_str("api_key") is Licensing.API_KEY
    assert Licensing.from_str(None) is Licensing.FREE
    assert Licensing.from_str("lixo") is Licensing.FREE  # default honesto


def test_tool_credential_from_dict():
    c = ToolCredential.from_dict(
        {"env": "WPSCAN_API_TOKEN", "label": "WPScan", "required": False, "degrades": "sem CVEs"}
    )
    assert c is not None and c.env == "WPSCAN_API_TOKEN" and not c.required
    assert ToolCredential.from_dict({"label": "sem env"}) is None  # env obrigatório
    assert ToolCredential.from_dict("não é dict") is None


def test_resolve_present_and_missing():
    creds = (_cred("KEY_A"), _cred("KEY_B", required=True))
    env = {"KEY_A": "valor", "KEY_B": "  "}  # B vazio/espaços = ausente
    states = resolve_credentials(creds, env)
    assert states[0].present and not states[0].missing_optional
    assert not states[1].present and states[1].missing_required


def test_coverage_warning_optional_gap():
    states = [
        CredentialState(_cred("A", degrades="perde X"), present=False),
        CredentialState(_cred("B", degrades="perde Y"), present=True),
    ]
    warn = coverage_warning("subfinder", states)
    assert warn is not None and "PARCIAL" in warn and "perde X" in warn and "perde Y" not in warn


def test_coverage_warning_none_when_all_present():
    states = [CredentialState(_cred("A"), present=True)]
    assert coverage_warning("wpscan", states) is None


def test_required_missing_is_not_coverage_gap():
    # credencial OBRIGATÓRIA ausente não é "cobertura parcial" (a ferramenta nem roda útil).
    states = [CredentialState(_cred("A", required=True), present=False)]
    assert coverage_warning("burp", states) is None


def test_metadata_parses_wpscan_credentials():
    reg = PluginRegistry.discover()
    wpscan = next(s for s in reg.all() if s.name == "wpscan")
    assert wpscan.metadata.licensing is Licensing.API_KEY
    envs = {c.env for c in wpscan.metadata.credentials}
    assert "WPSCAN_API_TOKEN" in envs
    assert all(not c.required for c in wpscan.metadata.credentials)  # opcional → degrada


def test_metadata_parses_subfinder_provider_credentials():
    reg = PluginRegistry.discover()
    sub = next(s for s in reg.all() if s.name == "subfinder")
    providers = {c.provider for c in sub.metadata.credentials}
    assert {"shodan", "censys", "virustotal", "securitytrails"} <= providers


def test_burp_is_paid_scaffold():
    reg = PluginRegistry.discover()
    burp = next(s for s in reg.all() if s.name == "burp")
    assert burp.metadata.licensing is Licensing.PAID
    assert burp.metadata.roadmap  # não executa
    assert not burp.available()
    # credencial obrigatória → requires_credentials derivado
    assert burp.metadata.requires_credentials


def test_spec_coverage_note_reflects_env(monkeypatch):
    reg = PluginRegistry.discover()
    wpscan = next(s for s in reg.all() if s.name == "wpscan")
    monkeypatch.delenv("WPSCAN_API_TOKEN", raising=False)
    assert wpscan.coverage_note() is not None  # sem token → parcial
    monkeypatch.setenv("WPSCAN_API_TOKEN", "tok")
    assert wpscan.coverage_note() is None  # com token → sem lacuna
