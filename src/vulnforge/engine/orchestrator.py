"""Orquestrador de scan.

Coordena os adapters de ferramenta respeitando escopo e perfil, normaliza e
deduplica os findings e persiste no store. É um caso de uso da camada de
aplicação: depende de portas (adapters, store, scope) e não de infra concreta.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..findings.dedup import deduplicate
from ..findings.schema import Finding
from ..findings.store import FindingStore
from ..security.scope import Scope, ScopeViolation
from .adapters.nmap_adapter import NmapAdapter
from .adapters.nuclei_adapter import NucleiAdapter
from .base import BaseToolAdapter, ToolNotAvailable

log = logging.getLogger("vulnforge.orchestrator")

# Perfis: quais adapters e opções por profile. Mantido simples e determinístico;
# em produção isto é carregado de config/profiles.yaml.
_REGISTRY: dict[str, BaseToolAdapter] = {
    "nmap": NmapAdapter(),
    "nuclei": NucleiAdapter(),
}

_PROFILES: dict[str, list[str]] = {
    "quick": ["nmap"],
    "standard": ["nmap", "nuclei"],
    "deep": ["nmap", "nuclei"],
    "network-only": ["nmap"],
    "web-only": ["nuclei"],
}


@dataclass
class ScanReport:
    scan_id: Optional[int]
    findings: list[Finding] = field(default_factory=list)
    skipped_tools: list[str] = field(default_factory=list)


ProgressCb = Callable[[str], None]


class Orchestrator:
    def __init__(self, store: Optional[FindingStore] = None,
                 registry: Optional[dict[str, BaseToolAdapter]] = None) -> None:
        self._store = store
        self._registry = registry or _REGISTRY

    def run(self, targets: list[str], *, scope: Scope, profile: str = "standard",
            progress: Optional[ProgressCb] = None, **tool_opts) -> ScanReport:
        if profile not in _PROFILES:
            raise ValueError(f"Perfil desconhecido: {profile!r}. Opções: {list(_PROFILES)}")

        # Guardrail: bloqueia por padrão qualquer alvo fora do escopo autorizado.
        for t in targets:
            scope.enforce(t)

        tools = _PROFILES[profile]
        raw: list[Finding] = []
        skipped: list[str] = []

        def emit(msg: str) -> None:
            log.info(msg)
            if progress:
                progress(msg)

        scan_id = None
        if self._store:
            scan_id = self._store.create_scan(scope.engagement, profile, targets)

        for target in targets:
            for tool_name in tools:
                adapter = self._registry[tool_name]
                emit(f"[{tool_name}] escaneando {target}")
                try:
                    raw.extend(adapter.scan(target, **tool_opts))
                except ToolNotAvailable as exc:
                    emit(f"[{tool_name}] indisponível: {exc}")
                    if tool_name not in skipped:
                        skipped.append(tool_name)
                except ScopeViolation:
                    raise
                except Exception as exc:  # noqa: BLE001 — um adapter não derruba o scan
                    emit(f"[{tool_name}] erro: {exc}")

        findings = deduplicate(raw)
        findings.sort(key=lambda f: f.severity.rank, reverse=True)

        if self._store and scan_id is not None:
            self._store.add_findings(scan_id, findings)
            self._store.finish_scan(scan_id)

        emit(f"scan concluído: {len(findings)} findings ({len(skipped)} ferramentas puladas)")
        return ScanReport(scan_id=scan_id, findings=findings, skipped_tools=skipped)
