"""Testes da intensidade de scan (perfil × perspectiva → opções de ferramenta)."""

from eigan.engine.tuning import tool_options
from eigan.perspective import Perspective


def test_stealth_is_low_and_slow():
    o = tool_options("stealth", Perspective.UNIFIED)
    assert o["stealth"] is True
    assert o["timing"] == 2  # nmap -T2
    assert o["rate_limit"] <= 40 and o["port_rate"] <= 100


def test_deep_scans_all_ports_with_effort():
    o = tool_options("deep", Perspective.UNIFIED)
    assert o["all_ports"] is True
    assert o["severity"] is None  # sem filtro: roda tudo do nuclei
    assert o["depth"] >= 3


def test_external_is_conservative_on_rate():
    # externo exposto segura o rate (não derrubar produção), sem furtividade.
    ext = tool_options("standard", Perspective.EXTERNAL)
    uni = tool_options("standard", Perspective.UNIFIED)
    assert ext["rate_limit"] <= uni["rate_limit"]
    assert ext["port_rate"] <= uni["port_rate"]


def test_unknown_profile_falls_back_to_standard():
    assert tool_options("qualquer-coisa", Perspective.UNIFIED) == tool_options(
        "standard", Perspective.UNIFIED
    )


def test_ai_alias_uses_standard_intensity():
    assert tool_options("ai", Perspective.UNIFIED) == tool_options("standard", Perspective.UNIFIED)
