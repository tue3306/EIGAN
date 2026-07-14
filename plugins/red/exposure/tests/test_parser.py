"""Testes do exposure prober (Red): classificador de exposição + scanner de segredos."""

from __future__ import annotations

from plugins.red.exposure.parser import classify, scan_secrets, sensitive_paths
from plugins.red.exposure.runner import _base_url


def test_classify_env_exposed():
    f = classify("/.env", "http://x/.env", 200, "DB_PASSWORD=secret\nAPI_KEY=abc\n")
    assert f is not None
    assert f.severity.value == "critical"
    assert f.cwe == "CWE-522" and f.attack_technique == "T1552"


def test_classify_git_config_exposed():
    f = classify("/.git/config", "http://x/.git/config", 200, "[core]\nrepositoryformatversion = 0")
    assert f is not None and f.attack_technique == "T1592" and f.severity.value == "high"


def test_classify_requires_signature_not_just_200():
    # 200 mas conteúdo é um soft-404/HTML genérico → NÃO afirma exposição (§3.1).
    assert classify("/.env", "http://x/.env", 200, "<html>404 Not Found</html>") is None


def test_classify_ignores_non_200():
    assert classify("/.env", "http://x/.env", 404, "DB_PASSWORD=x") is None


def test_scan_secrets_masks_aws_key():
    fs = scan_secrets("http://x", "config: AKIAIOSFODNN7EXAMPLE end")
    assert len(fs) == 1
    assert fs[0].cwe == "CWE-798" and fs[0].attack_technique == "T1552"
    assert "AKIAIOSFODNN7EXAMPLE" not in fs[0].evidence  # mascarado
    assert "AKIAIO" in fs[0].evidence


def test_scan_secrets_github_token():
    body = "token=ghp_" + ("a" * 36)
    fs = scan_secrets("http://x", body)
    assert any("GitHub" in f.title for f in fs)


def test_scan_secrets_private_key_and_dedup():
    body = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----BEGIN RSA PRIVATE KEY-----\n"
    fs = scan_secrets("http://x", body)
    assert len(fs) == 1  # dedup do mesmo token


def test_scan_secrets_none_on_clean_body():
    assert scan_secrets("http://x", "<html>página normal sem segredos</html>") == []


def test_base_url_normalization():
    assert _base_url("example.com") == "https://example.com"
    assert _base_url("http://example.com/app/") == "http://example.com/app"
    assert _base_url("https://x") == "https://x"


def test_sensitive_paths_curated():
    paths = sensitive_paths()
    assert "/.env" in paths and "/.git/config" in paths and "/.ssh/id_rsa" in paths
