"""Testes do guardrail de escopo — a barreira legal do produto.

Cobre a interação escopo × perspectiva (público×privado)."""

import pytest

from eigan.perspective import Perspective
from eigan.security.scope import PerspectiveViolation, Scope, ScopeViolation

INTERNAL = Perspective.INTERNAL
EXTERNAL = Perspective.EXTERNAL


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
