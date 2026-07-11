"""Testes do registry de plugins: auto-discovery real + isolamento de falhas.

Cobre o requisito arquitetural central (ADR-0001/0003): adicionar um plugin é só
criar uma pasta; um plugin quebrado NÃO derruba o registry.
"""

from pathlib import Path

from eigan.capability import Capability
from eigan.engine.registry import PluginRegistry
from eigan.perspective import Perspective


def test_discovers_first_party_plugins():
    reg = PluginRegistry.discover()
    names = {s.name for s in reg.all()}
    # os 6 plugins migrados devem estar presentes.
    assert {"nmap", "nuclei", "naabu", "dnsx", "httpx", "subfinder"} <= names


def test_capability_index_and_perspective_filter():
    reg = PluginRegistry.discover()
    # nmap é multi-capability: aparece em PORT_DISCOVERY e HOST_DISCOVERY.
    port = {s.name for s in reg.for_capability(Capability.PORT_DISCOVERY)}
    assert {"naabu", "nmap"} <= port
    # subfinder só EXTERNAL: some ao filtrar por INTERNAL.
    ext = {
        s.name for s in reg.for_capability(Capability.SUBDOMAIN_ENUMERATION, Perspective.EXTERNAL)
    }
    intr = {
        s.name for s in reg.for_capability(Capability.SUBDOMAIN_ENUMERATION, Perspective.INTERNAL)
    }
    assert "subfinder" in ext and "subfinder" not in intr


def test_broken_plugin_is_isolated(tmp_path: Path):
    """Metadados inválidos viram spec degradado; o bom continua carregando."""
    root = tmp_path / "plugins"
    (root / "red" / "broken").mkdir(parents=True)
    (root / "red" / "broken" / "metadata.yaml").write_text("name: broken\n")  # faltam campos

    (root / "red" / "ok").mkdir(parents=True)
    (root / "red" / "ok" / "metadata.yaml").write_text(
        "name: ok\ncategory: red\ncapabilities: [port_discovery]\n"
        "supported_perspectives: [external]\ntool: ok\nroadmap: true\n"
    )

    reg = PluginRegistry.discover(roots=[root])
    names = {s.name for s in reg.all()}
    assert {"broken", "ok"} <= names
    assert any(s.degraded for s in reg.all() if s.name == "broken")
    # o plugin 'ok' é roadmap: descoberto, catalogado, porém não disponível.
    ok = reg.get("ok")
    assert ok is not None and not ok.available()
