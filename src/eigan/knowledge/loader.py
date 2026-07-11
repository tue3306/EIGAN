"""Loader da base de conhecimento (padrão agentskills.io).

Cada skill é uma pasta com ``SKILL.md``: frontmatter YAML (metadados leves para
descoberta — *progressive disclosure*) + corpo Markdown com seções When to Use /
Prerequisites / Workflow / Verification / Remediation.

Serve aos dois modos (CLAUDE.md §6/§7):
- SEM IA: casa `cwe`/`owasp` do finding com a skill e usa Workflow/Remediation
  para preencher explicação e correção determinísticas.
- COM IA: as skills entram como contexto ancorado (grounding) para o provedor.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_FRONTMATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL)
_SECTION = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.MULTILINE)


@dataclass
class Skill:
    name: str
    description: str
    meta: dict = field(default_factory=dict)
    sections: dict[str, str] = field(default_factory=dict)
    path: Path | None = None

    @property
    def cwe(self) -> list[str]:
        v = self.meta.get("cwe", [])
        return [v] if isinstance(v, str) else [str(x) for x in v]

    @property
    def owasp(self) -> list[str]:
        v = self.meta.get("owasp", [])
        return [v] if isinstance(v, str) else [str(x) for x in v]

    def section(self, name: str) -> str:
        for k, v in self.sections.items():
            if k.lower() == name.lower():
                return v
        return ""


def parse_skill(text: str, path: Path | None = None) -> Skill:
    m = _FRONTMATTER.match(text)
    if not m:
        raise ValueError("SKILL.md sem frontmatter YAML válido")
    meta = yaml.safe_load(m.group(1)) or {}
    body = m.group(2)

    # divide o corpo por cabeçalhos markdown
    sections: dict[str, str] = {}
    matches = list(_SECTION.finditer(body))
    for i, sec in enumerate(matches):
        start = sec.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        sections[sec.group(1)] = body[start:end].strip()

    return Skill(
        name=str(meta.get("name", path.parent.name if path else "unknown")),
        description=str(meta.get("description", "")),
        meta=meta,
        sections=sections,
        path=path,
    )


class KnowledgeBase:
    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)
        self._skills: list[Skill] = []
        self._by_cwe: dict[str, Skill] = {}
        self._by_owasp: dict[str, Skill] = {}
        self._load()

    def _load(self) -> None:
        if not self._root.exists():
            return
        for skill_md in self._root.glob("**/SKILL.md"):
            try:
                skill = parse_skill(skill_md.read_text(), skill_md)
            except ValueError:
                continue
            self._skills.append(skill)
            for c in skill.cwe:
                self._by_cwe[c.upper()] = skill
            for o in skill.owasp:
                self._by_owasp[o.upper()] = skill

    def __len__(self) -> int:
        return len(self._skills)

    def match(self, *, cwe: str | None = None, owasp: str | None = None) -> Skill | None:
        if cwe and cwe.upper() in self._by_cwe:
            return self._by_cwe[cwe.upper()]
        if owasp and owasp.upper() in self._by_owasp:
            return self._by_owasp[owasp.upper()]
        return None

    def all(self) -> list[Skill]:
        return list(self._skills)
