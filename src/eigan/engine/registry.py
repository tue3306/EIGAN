"""Registry de plugins com auto-discovery (ADR-0001 / ADR-0003).

O Core **nunca muda** para adicionar um plugin: o registry varre as pastas de
plugins, lê cada ``metadata.yaml``, importa o ``runner.py`` e indexa por
capability. Adicionar uma ferramenta = criar uma pasta ``plugins/<cat>/<nome>/``.

Robustez (inegociável §6): um plugin com metadados inválidos ou import quebrado é
registrado como **degradado** (aparece no ``doctor``) e **não** derruba o
registry nem os demais plugins.
"""

from __future__ import annotations

import importlib
import logging
import os
import sys
from pathlib import Path

from ..capability import Capability
from ..perspective import Perspective
from .base import BaseToolPlugin
from .health import Health
from .plugin import PluginMetadata, PluginMetadataError, PluginSpec

log = logging.getLogger("eigan.registry")

# raiz do pacote e do repositório, para resolver as pastas de plugins.
_PKG_DIR = Path(__file__).resolve().parents[1]  # src/eigan
_REPO_ROOT = Path(__file__).resolve().parents[3]  # raiz do repo


class PluginLoadError(Exception):
    """Falha ao instanciar o runner de um plugin."""


def default_plugin_roots() -> list[Path]:
    """Raízes onde procurar plugins, em ordem de precedência.

    ``$EIGAN_PLUGINS_DIR`` (terceiros) → ``<repo>/plugins`` (primeira parte)
    → ``<pacote>/plugins`` (fallback empacotado em wheel). Só as existentes são
    usadas; duplicatas (por caminho resolvido) são removidas.
    """
    candidates: list[Path] = []
    env = os.getenv("EIGAN_PLUGINS_DIR")
    if env:
        candidates.append(Path(env))
    candidates.append(_REPO_ROOT / "plugins")
    candidates.append(_PKG_DIR / "plugins")

    seen: set[Path] = set()
    roots: list[Path] = []
    for c in candidates:
        try:
            rc = c.resolve()
        except OSError:
            continue
        if rc.is_dir() and rc not in seen:
            seen.add(rc)
            roots.append(rc)
    return roots


def _instantiate_runner(module) -> BaseToolPlugin:
    """Encontra e instancia a classe runner do módulo.

    Convenção: uma variável ``PLUGIN`` (classe ou instância) OU uma única
    subclasse de :class:`BaseToolPlugin` definida no próprio módulo.
    """
    plugin_obj = getattr(module, "PLUGIN", None)
    if plugin_obj is not None:
        return plugin_obj() if isinstance(plugin_obj, type) else plugin_obj

    candidates = [
        v
        for v in vars(module).values()
        if isinstance(v, type)
        and issubclass(v, BaseToolPlugin)
        and v is not BaseToolPlugin
        and v.__module__ == module.__name__
    ]
    if len(candidates) != 1:
        raise PluginLoadError(
            f"{module.__name__}: esperava 1 runner (subclasse de BaseToolPlugin) "
            f"ou uma variável PLUGIN; encontrei {len(candidates)}."
        )
    return candidates[0]()


class PluginRegistry:
    """Índice de plugins descobertos. Consultado pelo orquestrador por capability."""

    def __init__(self, specs: list[PluginSpec]) -> None:
        self._specs = specs
        self._by_name: dict[str, PluginSpec] = {}
        self._by_capability: dict[Capability, list[PluginSpec]] = {}
        for spec in specs:
            # nome duplicado: mantém o primeiro, registra aviso (determinístico).
            if spec.name in self._by_name:
                log.warning("plugin duplicado ignorado: %s", spec.name)
                continue
            self._by_name[spec.name] = spec
            for cap in spec.metadata.capabilities:
                self._by_capability.setdefault(cap, []).append(spec)

    # ── construção ────────────────────────────────────────────────────────────
    @classmethod
    def discover(cls, roots: list[Path] | None = None) -> "PluginRegistry":
        roots = roots if roots is not None else default_plugin_roots()
        specs: list[PluginSpec] = []
        for root in roots:
            specs.extend(cls._discover_root(root))
        return cls(specs)

    @staticmethod
    def _discover_root(root: Path) -> list[PluginSpec]:
        parent = str(root.parent)
        if parent not in sys.path:
            sys.path.insert(0, parent)  # habilita ``import <root>.<cat>.<nome>``
        specs: list[PluginSpec] = []
        for meta_path in sorted(root.glob("*/*/metadata.yaml")):
            specs.append(PluginRegistry._load_one(root, meta_path))
        return specs

    @staticmethod
    def _load_one(root: Path, meta_path: Path) -> PluginSpec:
        # 1) metadados (se inválidos, produz spec degradado mínimo).
        try:
            meta = PluginMetadata.from_yaml(meta_path)
        except (PluginMetadataError, OSError, ValueError) as exc:
            return _degraded_from_path(meta_path, str(exc))

        # 2) roadmap (scaffolded honesto): não importa runner; não executa.
        if meta.roadmap:
            return PluginSpec(metadata=meta, runner=None)

        # 3) importa o runner e instancia; isola qualquer falha como degradado.
        rel_parts = meta_path.parent.relative_to(root).parts  # (categoria, nome)
        module_name = ".".join((root.name, *rel_parts, "runner"))
        try:
            module = importlib.import_module(module_name)
            runner = _instantiate_runner(module)
        except Exception as exc:  # noqa: BLE001 — um plugin quebrado não derruba o registry
            log.warning("plugin %s degradado: %s", meta.name, exc)
            return PluginSpec(metadata=meta, runner=None, load_error=str(exc))
        return PluginSpec(metadata=meta, runner=runner)

    # ── consultas ─────────────────────────────────────────────────────────────
    def for_capability(
        self, capability: Capability, perspective: Perspective | None = None
    ) -> list[PluginSpec]:
        specs = self._by_capability.get(capability, [])
        if perspective is None:
            return list(specs)
        return [s for s in specs if s.runs_in(perspective)]

    def get(self, name: str) -> PluginSpec | None:
        return self._by_name.get(name)

    def all(self) -> list[PluginSpec]:
        return list(self._specs)

    def degraded(self) -> list[PluginSpec]:
        return [s for s in self._specs if s.degraded]

    def capabilities(self) -> set[Capability]:
        return set(self._by_capability)

    def health_report(self) -> list[Health]:
        """Saúde (§12) de todas as ferramentas do registry, ordenada por nome."""
        return [s.health_check() for s in sorted(self._specs, key=lambda s: s.name)]

    def __len__(self) -> int:
        return len(self._by_name)


def _degraded_from_path(meta_path: Path, error: str) -> PluginSpec:
    """Constrói um spec degradado quando nem os metadados carregaram, usando a
    pasta como nome para que o ``doctor`` consiga reportá-lo."""
    from ..capability import Category

    name = meta_path.parent.name
    placeholder = PluginMetadata(
        name=name,
        category=Category.RED,
        capabilities=(),
        supported_perspectives=(),
        tool=name,
        description="(metadados inválidos)",
        path=meta_path,
    )
    return PluginSpec(metadata=placeholder, runner=None, load_error=error)
