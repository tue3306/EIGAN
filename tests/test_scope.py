"""Testes do guardrail de escopo — a barreira legal do produto.

Cobre a interação escopo × perspectiva (público×privado)."""

import pytest

from eigan.perspective import Perspective, validate_target
from eigan.security.onboarding import build_scope
from eigan.security.scope import InvalidTarget, PerspectiveViolation, Scope, ScopeViolation

INTERNAL = Perspective.INTERNAL
EXTERNAL = Perspective.EXTERNAL
UNIFIED = Perspective.UNIFIED


# ── modo efêmero (default do produto): não bloqueia por lista ────────────────


def test_ephemeral_scope_does_not_block_targets():
    # A fricção que travava scans: uma URL não casava consigo mesma na allowlist.
    # No modo efêmero o consent gate é a autorização — nada é barrado por lista.
    scope = build_scope(None, ["https://demo.testfire.net/"], UNIFIED)
    assert scope.enforce_membership is False
    scope.enforce("https://demo.testfire.net/", perspective=UNIFIED)  # não levanta
    # um alvo diferente também não é barrado no modo efêmero
    scope.enforce("outro-alvo.example", perspective=UNIFIED)


def test_ephemeral_scope_still_validates_target_form():
    # Mesmo sem trava de lista, a forma do alvo (anti argument-injection) é barrada.
    scope = build_scope(None, ["example.com"], UNIFIED)
    with pytest.raises(InvalidTarget):
        scope.enforce("--script=x", perspective=UNIFIED)


def test_unified_scope_allows_private_and_public():
    # UNIFIED documenta o que achar: não recusa nem privado nem público.
    scope = build_scope(None, ["10.0.0.5"], UNIFIED)
    scope.enforce("10.0.0.5", perspective=UNIFIED)  # privado: não levanta
    scope.enforce("8.8.8.8", perspective=UNIFIED)  # público: não levanta


def test_cloud_metadata_blocked_always():
    """Metadata de nuvem (169.254.169.254) é bloqueado SEMPRE — nem override libera (ADR-0015)."""
    scope = build_scope(None, ["169.254.169.254"], UNIFIED)
    with pytest.raises(ScopeViolation):
        scope.enforce("169.254.169.254", perspective=UNIFIED)
    with pytest.raises(ScopeViolation):
        scope.enforce(
            "http://169.254.169.254/latest/meta-data/", perspective=UNIFIED, override=True
        )
    with pytest.raises(ScopeViolation):
        scope.enforce("metadata.google.internal", perspective=UNIFIED, override=True)


def test_hard_lock_from_file_still_enforces_membership(tmp_path):
    # A trava dura por arquivo (opt-in, times/CI) segue barrando fora da lista.
    p = tmp_path / "scope.yaml"
    p.write_text("authorized: true\nperspective: unified\nhosts:\n  - example.com\n")
    scope = Scope.load(p)
    assert scope.enforce_membership is True
    scope.enforce("example.com", perspective=UNIFIED)  # dentro: ok
    with pytest.raises(ScopeViolation):
        scope.enforce("fora.example.net", perspective=UNIFIED)


def test_blocks_when_not_authorized():
    scope = Scope(authorized=False, hosts=["127.0.0.1"])
    with pytest.raises(ScopeViolation):
        scope.enforce("127.0.0.1", perspective=INTERNAL)


def test_blocks_target_outside_scope():
    scope = Scope(authorized=True, hosts=["10.0.0.5"])
    with pytest.raises(ScopeViolation):
        scope.enforce("10.0.0.6", perspective=INTERNAL)


def test_allows_authorized_private_host_internal():
    scope = Scope(authorized=True, hosts=["127.0.0.1"])
    scope.enforce("127.0.0.1", perspective=INTERNAL)  # não levanta


def test_cidr_match():
    scope = Scope(authorized=True, hosts=["10.0.0.0/24"])
    assert scope.contains("10.0.0.42")
    assert not scope.contains("10.0.1.1")


def test_url_target_extracts_host():
    scope = Scope(authorized=True, hosts=["example.com"])
    assert scope.contains("https://example.com:8443/path")


def test_wildcard_subdomain():
    scope = Scope(authorized=True, hosts=["*.lab.internal"])
    assert scope.contains("app.lab.internal")
    assert scope.contains("lab.internal")
    assert not scope.contains("evil.com")


def test_exclude_takes_precedence():
    scope = Scope(authorized=True, hosts=["10.0.0.0/24"], exclude=["10.0.0.5"])
    assert not scope.contains("10.0.0.5")
    assert scope.contains("10.0.0.6")


# ── perspectiva × escopo ────────────────────────────────────────────────────


def test_external_blocks_private_target():
    scope = Scope(authorized=True, hosts=["10.0.0.5"], perspective=EXTERNAL)
    with pytest.raises(PerspectiveViolation):
        scope.enforce("10.0.0.5", perspective=EXTERNAL)


def test_internal_blocks_public_target():
    scope = Scope(authorized=True, hosts=["8.8.8.8"], perspective=INTERNAL)
    with pytest.raises(PerspectiveViolation):
        scope.enforce("8.8.8.8", perspective=INTERNAL)


def test_override_allows_perspective_mismatch_but_not_scope():
    scope = Scope(authorized=True, hosts=["10.0.0.5"], perspective=EXTERNAL)
    # override libera a regra público×privado…
    scope.enforce("10.0.0.5", perspective=EXTERNAL, override=True)
    # …mas NÃO libera pertencimento ao escopo:
    with pytest.raises(ScopeViolation):
        scope.enforce("10.0.0.9", perspective=EXTERNAL, override=True)


def test_perspective_from_scope_used_when_not_passed():
    scope = Scope(authorized=True, hosts=["10.0.0.5"], perspective=INTERNAL)
    scope.enforce("10.0.0.5")  # usa a perspectiva do próprio scope


# ── forma do alvo (anti argument-injection, §5) ─────────────────────────────


@pytest.mark.parametrize(
    "target",
    [
        "-oN",  # flag do nmap
        "--script=http-shellshock",  # execução de NSE via flag
        "-iL/etc/passwd",
        "  ",  # só espaço
        "",  # vazio
        "exemplo .com",  # espaço no meio
        "host\tname",  # tab
        "host\nname",  # quebra de linha
        "host\x00name",  # NUL
    ],
)
def test_validate_target_rejects_malformed(target):
    with pytest.raises(ValueError):
        validate_target(target)


@pytest.mark.parametrize(
    "target",
    ["example.com", "10.0.0.5", "example.com:8443", "https://example.com/path?q=1", "[::1]:80"],
)
def test_validate_target_accepts_valid(target):
    assert validate_target(target) == target.strip()


def test_enforce_rejects_argument_injection_even_if_in_scope():
    # Alvo malformado é barrado ANTES do escopo — nunca chega a um runner, mesmo
    # que (num escopo efêmero) ele "pertença" ao escopo por ser um dos alvos.
    scope = Scope(authorized=True, hosts=["--script=x"], perspective=INTERNAL)
    with pytest.raises(InvalidTarget):
        scope.enforce("--script=x", perspective=INTERNAL)
