"""Testes da blindagem de SSRF (ADR-0015): classificação, triagem, redirect, rebinding."""

from __future__ import annotations

import socket

import pytest

from eigan.security import ssrf


def test_ip_category():
    assert ssrf.ip_category("169.254.169.254") == "metadata"
    assert ssrf.ip_category("100.100.100.100") == "metadata"
    assert ssrf.ip_category("127.0.0.1") == "loopback"
    assert ssrf.ip_category("10.0.0.5") == "private"
    assert ssrf.ip_category("192.168.1.1") == "private"
    assert ssrf.ip_category("fd00::1") == "private"  # ULA
    assert ssrf.ip_category("8.8.8.8") == "public"
    assert ssrf.ip_category("169.254.1.1") == "link-local"


def test_is_metadata_literal():
    assert ssrf.is_metadata_literal("169.254.169.254")
    assert ssrf.is_metadata_literal("metadata.google.internal")
    assert not ssrf.is_metadata_literal("example.com")
    assert not ssrf.is_metadata_literal("10.0.0.1")


def test_screen_ip_metadata_always_blocked():
    with pytest.raises(ssrf.SsrfError):
        ssrf.screen_ip("169.254.169.254", allow_private=True)  # nem com allow_private
    with pytest.raises(ssrf.SsrfError):
        ssrf.screen_ip("169.254.169.254", allow_private=False)


def test_screen_ip_private_gated_by_allow():
    ssrf.screen_ip("10.0.0.5", allow_private=True)  # ok em interno/unificado
    with pytest.raises(ssrf.SsrfError):
        ssrf.screen_ip("10.0.0.5", allow_private=False)  # bloqueado no externo
    ssrf.screen_ip("8.8.8.8", allow_private=False)  # público sempre ok


def test_ipv4_mapped_ipv6_metadata_normalized():
    """IPv4-mapped IPv6 (``::ffff:169.254.169.254``) roteia para o metadata real:
    tem de ser classificado como metadata, não link-local — senão em assumed-breach
    (allow_private=True) o bloqueio 'sempre' de metadata é furado (SSRF → roubo de
    credencial de nuvem). Regressão."""
    assert ssrf.ip_category("::ffff:169.254.169.254") == "metadata"
    assert ssrf.ip_category("::ffff:100.100.100.100") == "metadata"
    assert ssrf.ip_category("::ffff:10.0.0.5") == "private"
    assert ssrf.ip_category("::ffff:127.0.0.1") == "loopback"
    assert ssrf.is_metadata_literal("::ffff:169.254.169.254")
    assert ssrf.is_metadata_literal("[::ffff:169.254.169.254]")


def test_screen_ip_metadata_always_blocked_even_ipv4_mapped():
    # nem com allow_private=True (assumed-breach) — metadata é bloqueado SEMPRE.
    with pytest.raises(ssrf.SsrfError):
        ssrf.screen_ip("::ffff:169.254.169.254", allow_private=True)
    with pytest.raises(ssrf.SsrfError):
        ssrf.screen_ip("::ffff:169.254.169.254", allow_private=False)


def test_resolve_and_screen_blocks_ipv4_mapped_metadata(monkeypatch):
    """DNS-rebinding com AAAA IPv4-mapped apontando pro metadata é bloqueado mesmo
    em assumed-breach (allow_private=True)."""
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo({"evil6": "::ffff:169.254.169.254"})
    )
    with pytest.raises(ssrf.SsrfError):
        ssrf.resolve_and_screen("evil6", allow_private=True)


def _fake_getaddrinfo(mapping):
    def _gai(host, *_a, **_k):
        ip = mapping.get(host)
        if ip is None:
            raise socket.gaierror(f"no {host}")
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 0))]

    return _gai


def test_resolve_and_screen_blocks_host_resolving_to_metadata(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo({"evil": "169.254.169.254"}))
    with pytest.raises(ssrf.SsrfError):
        ssrf.resolve_and_screen("evil", allow_private=True)


def test_resolve_and_screen_ok_public(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo({"ok": "93.184.216.34"}))
    assert ssrf.resolve_and_screen("ok", allow_private=False) == ["93.184.216.34"]


# ── safe_get: redirect + pinning ──────────────────────────────────────────────
class _FakeResp:
    def __init__(self, status, headers=None, body=b""):
        self.status = status
        self.headers = headers or {}
        self._body = body

    def read(self, n=None):
        return self._body if n is None else self._body[:n]


class _FakeConn:
    def __init__(self, responses):
        self._responses = list(responses)
        self.requests = []

    def request(self, method, path, headers):
        self.requests.append((path, headers))

    def getresponse(self):
        return self._responses.pop(0)

    def close(self):
        pass


def test_safe_get_follows_safe_redirect(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo({"good.test": "93.184.216.34"}))
    conns = iter(
        [
            _FakeConn([_FakeResp(302, {"Location": "http://good.test/next"})]),
            _FakeConn([_FakeResp(200, {}, b"conteudo final")]),
        ]
    )
    monkeypatch.setattr(ssrf, "_make_conn", lambda *a, **k: next(conns))
    out = ssrf.safe_get("http://good.test/", allow_private=False)
    assert out is not None
    status, body, final = out
    assert status == 200 and "conteudo final" in body and final.endswith("/next")


def test_safe_get_blocks_redirect_to_metadata(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        _fake_getaddrinfo({"good.test": "93.184.216.34", "evil.test": "169.254.169.254"}),
    )
    conns = iter([_FakeConn([_FakeResp(302, {"Location": "http://evil.test/"})])])
    monkeypatch.setattr(ssrf, "_make_conn", lambda *a, **k: next(conns))
    with pytest.raises(ssrf.SsrfError):
        ssrf.safe_get("http://good.test/", allow_private=False)


def test_safe_get_pins_to_resolved_ip(monkeypatch):
    """A conexão é feita ao IP validado, com Host header do nome (anti-rebinding)."""
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo({"good.test": "93.184.216.34"}))
    captured = {}

    def _mk(scheme, ip, port, timeout):
        captured["ip"] = ip
        return _FakeConn([_FakeResp(200, {}, b"ok")])

    monkeypatch.setattr(ssrf, "_make_conn", _mk)
    out = ssrf.safe_get("http://good.test/x", allow_private=False)
    assert out[0] == 200
    assert captured["ip"] == "93.184.216.34"  # conectou ao IP resolvido, não ao nome
