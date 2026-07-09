"""Grafo de cascata dirigido por descoberta (ADR-0004).

A "cascata" não é uma sequência rígida: é **dirigida pelo que foi descoberto**.
Cada plugin declara, em seu ``metadata.yaml``, regras ``triggers_on`` — condições
sobre um :class:`~vulnforge.findings.schema.Finding` que, quando satisfeitas,
sugerem executar outras ferramentas. Exemplo canônico: encontrar a porta 445
(SMB) aberta ⇒ disparar ``enum4linux`` + ``cme_smb_recon``.

Princípios (inegociáveis do CLAUDE.md):

* **Determinístico e sem mágica.** O casamento de regra é lógica pura sobre os
  campos normalizados do finding — nenhuma IA decide o que executar aqui. Cada
  disparo carrega uma *justificativa* legível (por que disparou) para o log e a
  UI (§3.2 do prompt de interface, "sem magia").
* **Capabilities, não ferramentas.** As regras casam por porta/serviço/severidade,
  então uma regra declarada no ``nmap`` também dispara a partir de findings do
  ``naabu`` — quem provê a descoberta é intercambiável.
* **Domínio puro.** Este módulo não faz I/O nem importa infraestrutura; só depende
  do schema de :class:`Finding`. A *execução* dos disparos é responsabilidade do
  :class:`~vulnforge.engine.cascade_orchestrator.CascadeOrchestrator`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterable, Optional

from ..findings.schema import Finding, Severity

if TYPE_CHECKING:  # evita ciclo em runtime (registry importa plugin importa isto)
    from .registry import PluginRegistry

# porta ao final de ``host:porta`` (afeta ``affected_asset`` de findings de rede).
_PORT_RE = re.compile(r":(\d{1,5})(?:/\w+)?$")
# serviço declarado entre parênteses no título ("Porta aberta 445/tcp (microsoft-ds)").
_SERVICE_RE = re.compile(r"\(([^)]+)\)")


def _as_int_tuple(value: object) -> tuple[int, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        out: list[int] = []
        for v in value:
            try:
                out.append(int(v))
            except (TypeError, ValueError):
                continue
        return tuple(out)
    if isinstance(value, (int, str)):
        try:
            return (int(value),)
        except ValueError:
            return ()
    return ()


def _as_str_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value.strip().lower(),)
    if isinstance(value, (list, tuple)):
        return tuple(str(v).strip().lower() for v in value if str(v).strip())
    return (str(value).strip().lower(),)


@dataclass(frozen=True)
class FindingFeatures:
    """Sinais extraídos de um finding para casar contra as regras de cascata.

    Extração determinística: a porta vem do sufixo ``:N`` de ``affected_asset`` e
    o serviço do trecho entre parênteses do título (convenção dos parsers de
    rede). Campos ausentes ficam ``None``/vazios e simplesmente não casam.
    """

    port: Optional[int]
    service: Optional[str]
    severity: Severity
    source_tool: str
    title: str
    cwe: Optional[str]

    @classmethod
    def of(cls, finding: Finding) -> "FindingFeatures":
        port: Optional[int] = None
        m = _PORT_RE.search(finding.affected_asset)
        if m:
            p = int(m.group(1))
            if 0 < p <= 65535:
                port = p
        svc: Optional[str] = None
        ms = _SERVICE_RE.search(finding.title)
        if ms:
            svc = ms.group(1).strip().lower()
        return cls(
            port=port,
            service=svc,
            severity=finding.severity,
            source_tool=finding.source_tool.lower(),
            title=finding.title.lower(),
            cwe=(finding.cwe or None),
        )


@dataclass(frozen=True)
class CascadeRule:
    """Uma condição declarada em ``triggers_on`` + as ferramentas a disparar.

    Todas as condições preenchidas devem casar (AND). Uma condição vazia é
    "qualquer". ``execute`` é obrigatório e não pode ser vazio.
    """

    execute: tuple[str, ...]
    port: tuple[int, ...] = ()
    service: tuple[str, ...] = ()
    source_tool: tuple[str, ...] = ()
    title_contains: tuple[str, ...] = ()
    severity_min: Optional[Severity] = None
    reason: str = ""

    @classmethod
    def from_dict(cls, data: object) -> Optional["CascadeRule"]:
        """Constrói a partir de um item de ``triggers_on`` do YAML.

        Aceita ``then_execute`` (nome usado no prompt) ou ``execute``. Regras sem
        ferramentas a executar são ignoradas (retorna ``None``) — scaffold honesto
        em vez de regra silenciosamente inerte.
        """
        if not isinstance(data, dict):
            return None
        execute = _as_str_tuple(data.get("execute") or data.get("then_execute"))
        if not execute:
            return None
        sev_raw = data.get("severity_min") or data.get("severity")
        severity_min: Optional[Severity] = None
        if sev_raw is not None:
            try:
                severity_min = Severity(str(sev_raw).strip().lower())
            except ValueError:
                severity_min = None
        return cls(
            execute=execute,
            port=_as_int_tuple(data.get("port")),
            service=_as_str_tuple(data.get("service")),
            source_tool=_as_str_tuple(data.get("source_tool")),
            title_contains=_as_str_tuple(data.get("title_contains")),
            severity_min=severity_min,
            reason=str(data.get("reason", "")).strip(),
        )

    def matches(self, feat: FindingFeatures) -> bool:
        if self.port and feat.port not in self.port:
            return False
        if self.service:
            hay = f"{feat.service or ''} {feat.title}"
            if not any(s in hay for s in self.service):
                return False
        if self.source_tool and feat.source_tool not in self.source_tool:
            return False
        if self.title_contains and not any(t in feat.title for t in self.title_contains):
            return False
        if self.severity_min and feat.severity.rank < self.severity_min.rank:
            return False
        return True

    def describe(self, feat: FindingFeatures) -> str:
        """Justificativa legível para log/UI — nunca um disparo sem explicação."""
        if self.reason:
            return self.reason
        bits: list[str] = []
        if self.port and feat.port is not None:
            bits.append(f"porta {feat.port}")
        if self.service and feat.service:
            bits.append(f"serviço {feat.service}")
        if self.severity_min:
            bits.append(f"severidade ≥ {self.severity_min.value}")
        if self.title_contains:
            bits.append(f"'{self.title_contains[0]}'")
        cond = ", ".join(bits) if bits else "descoberta"
        return f"{cond} → dispara {', '.join(self.execute)}"


@dataclass(frozen=True)
class CascadeTrigger:
    """Um disparo resolvido: qual ferramenta, por causa de qual finding e por quê."""

    tool: str
    reason: str
    declared_by: str  # plugin que declarou a regra
    source_finding: Finding


@dataclass
class CascadeGraph:
    """Agrega as regras ``triggers_on`` de todos os plugins e resolve disparos.

    Consulta central da cascata: dado um finding, quais ferramentas ele aciona e
    com que justificativa. Puro — não executa nada, apenas decide.
    """

    #: plugin declarante → suas regras
    rules_by_plugin: dict[str, tuple[CascadeRule, ...]] = field(default_factory=dict)

    @classmethod
    def from_registry(cls, registry: "PluginRegistry") -> "CascadeGraph":
        rules: dict[str, tuple[CascadeRule, ...]] = {}
        for spec in registry.all():
            triggers = getattr(spec.metadata, "triggers_on", ())
            if triggers:
                rules[spec.name] = triggers
        return cls(rules_by_plugin=rules)

    def triggered_by(self, finding: Finding) -> list[CascadeTrigger]:
        """Ferramentas acionadas por um finding, deduplicadas e ordenadas.

        Determinístico: itera plugins e regras em ordem estável; a primeira
        justificativa vence para cada ferramenta (evita disparo duplicado)."""
        feat = FindingFeatures.of(finding)
        seen: set[str] = set()
        out: list[CascadeTrigger] = []
        for plugin_name in sorted(self.rules_by_plugin):
            for rule in self.rules_by_plugin[plugin_name]:
                if not rule.matches(feat):
                    continue
                reason = rule.describe(feat)
                for tool in rule.execute:
                    if tool in seen or tool == finding.source_tool.lower():
                        continue
                    seen.add(tool)
                    out.append(
                        CascadeTrigger(
                            tool=tool,
                            reason=reason,
                            declared_by=plugin_name,
                            source_finding=finding,
                        )
                    )
        return out

    def triggered_by_all(self, findings: Iterable[Finding]) -> list[CascadeTrigger]:
        """Disparos para um conjunto de findings, deduplicados por ferramenta.

        Usado para a onda de cascata pós-estágio: o primeiro finding que aciona
        uma ferramenta é quem a justifica no log."""
        seen: set[str] = set()
        out: list[CascadeTrigger] = []
        for f in findings:
            for trig in self.triggered_by(f):
                if trig.tool in seen:
                    continue
                seen.add(trig.tool)
                out.append(trig)
        return out

    def __bool__(self) -> bool:
        return bool(self.rules_by_plugin)
