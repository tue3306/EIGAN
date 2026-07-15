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


def test_health_report_classifies_tools(tmp_path: Path):
    """health_check (§12): roadmap→roadmap, metadados inválidos→degraded; status é
    sempre do conjunto válido (nada inventado, §2)."""
    from eigan.engine.health import Health

    root = tmp_path / "plugins"
    (root / "red" / "ok").mkdir(parents=True)
    (root / "red" / "ok" / "metadata.yaml").write_text(
        "name: ok\ncategory: red\ncapabilities: [port_discovery]\n"
        "supported_perspectives: [external]\ntool: ok\nroadmap: true\n"
    )
    (root / "red" / "broken").mkdir(parents=True)
    (root / "red" / "broken" / "metadata.yaml").write_text("name: broken\n")

    report = PluginRegistry.discover(roots=[root]).health_report()
    assert report and all(isinstance(h, Health) for h in report)
    by_name = {h.name: h for h in report}
    assert by_name["ok"].status == "roadmap" and by_name["ok"].available is False
    assert by_name["broken"].status == "degraded" and by_name["broken"].available is False
    assert {h.status for h in report} <= {"ok", "missing", "roadmap", "degraded"}


def test_health_check_reports_available_when_binary_on_path():
    """Uma ferramenta cujo binário existe no PATH sai como 'ok' com binary_path real."""
    from eigan.capability import Category
    from eigan.engine.base import BaseToolPlugin
    from eigan.engine.plugin import PluginMetadata, PluginSpec

    class _Echo(BaseToolPlugin):
        binary = "python3"  # garantidamente no PATH do ambiente de teste
        name = "echo"

        def build_args(self, target, **options):
            return [target]

        def parse(self, result, target):
            return []

    meta = PluginMetadata(
        name="echo",
        category=Category.RED,
        capabilities=(),
        supported_perspectives=(),
        tool="python3",
    )
    h = PluginSpec(metadata=meta, runner=_Echo()).health_check()
    assert h.status == "ok" and h.available is True and h.binary_path.endswith("python3")
