"""Testes do guardrail de escopo — a barreira legal do produto."""

import pytest

from vulnforge.security.scope import Scope, ScopeViolation


def test_blocks_when_not_authorized():
    scope = Scope(authorized=False, hosts=["127.0.0.1"])
    with pytest.raises(ScopeViolation):
        scope.enforce("127.0.0.1")


def test_blocks_target_outside_scope():
    scope = Scope(authorized=True, hosts=["10.0.0.5"])
    with pytest.raises(ScopeViolation):
        scope.enforce("8.8.8.8")


def test_allows_authorized_host():
    scope = Scope(authorized=True, hosts=["127.0.0.1"])
    scope.enforce("127.0.0.1")  # não levanta


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
