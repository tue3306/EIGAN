"""Schema normalizado de finding.

Contrato único para qualquer vulnerabilidade, independente da ferramenta de
origem. Todo adapter do engine deve produzir instâncias de :class:`Finding`;
todo consumidor (store, report, IA) depende apenas deste schema — nunca do
formato bruto de uma ferramenta específica. Este é o núcleo do domínio e não
conhece I/O.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from ..perspective import Perspective


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    """Severidade normalizada. A ordem numérica (ver :meth:`rank`) é usada para
    ordenação e para o gate ``--fail-on`` do CLI."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Mapeia score CVSS (0-10) para severidade seguindo as faixas
        qualitativas oficiais do CVSS v3.1 (spec FIRST)."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    FIRM = "firm"
    TENTATIVE = "tentative"
    UNVERIFIED = "unverified"  # dado não confirmado contra fonte oficial


class FindingStatus(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class CVSS(BaseModel):
    """Score CVSS com a versão sempre explícita — a versão nunca é assumida
    (regra anti-invenção do CLAUDE.md §5)."""

    version: str = Field(description="Ex.: '3.1' ou '4.0'. Nunca assumir.")
    score: float = Field(ge=0.0, le=10.0)
    vector: Optional[str] = None


class Finding(BaseModel):
    """Vulnerabilidade normalizada. `fingerprint` é derivado deterministicamente
    e usado para deduplicação/correlação entre ferramentas."""

    title: str
    severity: Severity
    affected_asset: str = Field(description="host, URL, porta ou pacote afetado")
    source_tool: str
    # perspectiva em que o finding foi obtido; carimbada pelo orquestrador.
    perspective: Perspective = Perspective.EXTERNAL

    cvss: Optional[CVSS] = None
    cwe: Optional[str] = Field(default=None, description="ex.: 'CWE-89'")
    owasp: Optional[str] = Field(default=None, description="ex.: 'A03:2021'")
    attack_technique: Optional[str] = Field(default=None, description="ex.: 'T1190'")

    description: str = ""
    evidence: str = ""
    reproduction: str = ""
    references: list[str] = Field(default_factory=list)

    confidence: Confidence = Confidence.TENTATIVE
    status: FindingStatus = FindingStatus.OPEN
    ai_generated: bool = False

    first_seen: datetime = Field(default_factory=_now)
    last_seen: datetime = Field(default_factory=_now)

    # Evidências adicionais quando o mesmo finding vem de múltiplas ferramentas.
    correlated_sources: list[str] = Field(default_factory=list)

    @field_validator("cwe")
    @classmethod
    def _cwe_format(cls, v: Optional[str]) -> Optional[str]:
        if v and not v.upper().startswith("CWE-"):
            raise ValueError("cwe deve estar no formato 'CWE-<n>'")
        return v.upper() if v else v

    @property
    def fingerprint(self) -> str:
        """Identidade estável para dedup: mesma vuln, mesmo asset, mesma classe
        (CWE) e mesma PERSPECTIVA => mesmo fingerprint, independente da ferramenta
        que reportou. A perspectiva entra na base porque um mesmo host pode ter
        findings externos e internos distintos que NÃO devem ser fundidos."""
        basis = "|".join(
            [
                self.perspective.value,
                (self.cwe or self.title).lower().strip(),
                self.affected_asset.lower().strip(),
            ]
        )
        return hashlib.sha256(basis.encode()).hexdigest()[:16]
