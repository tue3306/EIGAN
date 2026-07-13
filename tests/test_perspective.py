"""Testes da abstração de perspectiva (classificação de host + política)."""

from eigan.perspective import (
    HostClass,
    Perspective,
    classify_host,
    extract_host,
    profile_for,
    target_allowed,
)

EXTERNAL = Perspective.EXTERNAL
INTERNAL = Perspective.INTERNAL


def test_classify_host():
    assert classify_host("8.8.8.8") == HostClass.PUBLIC
    assert classify_host("10.0.0.1") == HostClass.PRIVATE
    assert classify_host("192.168.1.1") == HostClass.PRIVATE
    assert classify_host("127.0.0.1") == HostClass.LOOPBACK
    assert classify_host("169.254.1.1") == HostClass.LINK_LOCAL
    assert classify_host("example.com") == HostClass.HOSTNAME


def test_extract_host():
    assert extract_host("https://example.com:8443/x") == "example.com"
    assert extract_host("10.0.0.1:8080") == "10.0.0.1"
    assert extract_host("host.local") == "host.local"


def test_external_policy_blocks_private_and_loopback():
    ok, _ = target_allowed(EXTERNAL, "10.0.0.1")
    assert not ok
    ok, _ = target_allowed(EXTERNAL, "127.0.0.1")
    assert not ok
    ok, _ = target_allowed(EXTERNAL, "93.184.216.34")  # público
    assert ok


def test_internal_policy_blocks_public():
    ok, _ = target_allowed(INTERNAL, "8.8.8.8")
    assert not ok
    ok, _ = target_allowed(INTERNAL, "10.0.0.1")
    assert ok
    ok, _ = target_allowed(INTERNAL, "127.0.0.1")
    assert ok


def test_hostname_allowed_in_both():
    assert target_allowed(EXTERNAL, "example.com")[0]
    assert target_allowed(INTERNAL, "dc01.corp.local")[0]


def test_override_forces_allow_with_reason():
    ok, reason = target_allowed(EXTERNAL, "10.0.0.1", override=True)
    assert ok and "OVERRIDE" in reason


def test_unified_allows_all_host_classes():
    # Modo produto: nunca bloqueia por público×privado — documenta o que achar.
    for host in ("8.8.8.8", "10.0.0.1", "192.168.1.1", "127.0.0.1", "example.com"):
        assert target_allowed(Perspective.UNIFIED, host)[0], host


def test_profiles_differ():
    ext = profile_for(EXTERNAL)
    intr = profile_for(INTERNAL)
    assert ext.osint_subdomains and not intr.osint_subdomains
    assert intr.allow_credentials and not ext.allow_credentials
    assert intr.default_rate_limit >= ext.default_rate_limit
