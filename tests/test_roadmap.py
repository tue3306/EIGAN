"""Contrato de honestidade dos scaffolds (§B): descobertos, catalogados, mas
NÃO executáveis. Cada módulo de roadmap tem um teste marcado ``skip`` que
documenta a implementação futura — nunca um stub que finge passar.
"""

import pytest

from vulnforge.engine.registry import PluginRegistry

_REG = PluginRegistry.discover()
_ROADMAP = sorted(s.name for s in _REG.all() if s.metadata.roadmap)


def test_roadmap_plugins_discovered_but_not_available():
    assert _ROADMAP, "esperava scaffolds de roadmap descobertos"
    for spec in _REG.all():
        if spec.metadata.roadmap:
            # honesto: catalogado, porém não finge estar disponível.
            assert spec.available() is False
            assert spec.metadata.enabled_by_default is False


@pytest.mark.parametrize("name", _ROADMAP)
@pytest.mark.skip(reason="roadmap: módulo scaffolded, ainda não implementado (§B)")
def test_roadmap_module_implementation(name):
    """Placeholder da implementação futura de cada módulo de roadmap."""
