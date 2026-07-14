"""Resolução de wordlists — SecLists quando houver, com fallback honesto (ADR-0019).

Pentest de verdade usa **SecLists** (milhares a milhões de entradas). O EIGAN:

- **detecta SecLists** (e wordlists comuns do SO) e escolhe a de tamanho adequado
  ao **perfil** (quick→pequena, standard→média, deep→grande) e ao **objetivo**
  (conteúdo/diretório · parâmetro · subdomínio);
- se nada disso existe, cai para uma lista **curada MÉDIA embutida** e **AVISA** que
  a cobertura é reduzida (§3.1 — nunca fingir cobertura ampla);
- respeita `EIGAN_WORDLIST_DIR` (raiz do SecLists) para override explícito.

Puro e testável: só resolve caminhos (sem I/O de rede). O aviso de cobertura vai
para a timeline/doctor — o operador sabe exatamente o que está sendo usado."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# Objetivos de fuzzing e o tamanho por perfil.
_KINDS = ("content", "params", "dns")
_SIZE_BY_PROFILE = {"quick": "small", "standard": "medium", "deep": "large"}

# Raízes onde o SecLists costuma estar instalado (Kali/apt, git clone, brew).
_SECLISTS_ROOTS = (
    "/usr/share/seclists",
    "/usr/share/wordlists/seclists",
    "/opt/SecLists",
    str(Path.home() / "SecLists"),
)

# Caminho dentro do SecLists por (objetivo, tamanho). Verificados na estrutura
# oficial do SecLists (Discovery/Web-Content, Discovery/DNS).
_SECLISTS_REL = {
    ("content", "small"): "Discovery/Web-Content/common.txt",
    ("content", "medium"): "Discovery/Web-Content/directory-list-2.3-medium.txt",
    ("content", "large"): "Discovery/Web-Content/directory-list-2.3-big.txt",
    ("params", "small"): "Discovery/Web-Content/burp-parameter-names.txt",
    ("params", "medium"): "Discovery/Web-Content/burp-parameter-names.txt",
    ("params", "large"): "Discovery/Web-Content/raft-large-words.txt",
    ("dns", "small"): "Discovery/DNS/subdomains-top1million-5000.txt",
    ("dns", "medium"): "Discovery/DNS/subdomains-top1million-20000.txt",
    ("dns", "large"): "Discovery/DNS/subdomains-top1million-110000.txt",
}

# Wordlists comuns do SO (não-SecLists) como 2º melhor, por objetivo.
_SYSTEM_FALLBACKS = {
    "content": (
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    ),
    "params": ("/usr/share/wordlists/dirb/common.txt",),
    "dns": ("/usr/share/wordlists/dnsmap.txt",),
}

# Fallback embutido (curado, MÉDIO) — bem maior que a lista de 80 antiga.
_BUILTIN = {
    "content": Path(__file__).with_name("wordlists_data") / "content-medium.txt",
    "params": Path(__file__).with_name("wordlists_data") / "params-medium.txt",
    "dns": Path(__file__).with_name("wordlists_data") / "dns-medium.txt",
}


@dataclass(frozen=True)
class WordlistChoice:
    """Wordlist resolvida + procedência (para auditoria/doctor)."""

    path: str
    source: str  # "seclists" | "system" | "builtin"
    kind: str
    size: str

    @property
    def reduced_coverage(self) -> bool:
        return self.source == "builtin"

    def note(self) -> str:
        if self.source == "seclists":
            return f"SecLists {self.kind}/{self.size}: {self.path}"
        if self.source == "system":
            return f"wordlist do SO ({self.kind}): {self.path}"
        return (
            f"wordlist EMBUTIDA ({self.kind}, cobertura REDUZIDA — instale SecLists "
            f"para varredura ampla): {self.path}"
        )


def _size_for(profile: str) -> str:
    return _SIZE_BY_PROFILE.get((profile or "standard").strip().lower(), "medium")


def _seclists_roots() -> list[str]:
    roots: list[str] = []
    env = os.getenv("EIGAN_WORDLIST_DIR")
    if env:
        roots.append(env)
    roots.extend(_SECLISTS_ROOTS)
    return roots


def seclists_root() -> str | None:
    """Raiz do SecLists detectada (ou o override por env), se existir."""
    for root in _seclists_roots():
        if root and os.path.isdir(root):
            return root
    return None


def resolve(kind: str = "content", profile: str = "standard") -> WordlistChoice:
    """Resolve a melhor wordlist para ``kind``×``profile``, com procedência honesta."""
    if kind not in _KINDS:
        kind = "content"
    size = _size_for(profile)

    root = seclists_root()
    if root:
        rel = _SECLISTS_REL.get((kind, size)) or _SECLISTS_REL.get((kind, "medium"))
        if rel:
            candidate = os.path.join(root, rel)
            if os.path.isfile(candidate):
                return WordlistChoice(candidate, "seclists", kind, size)
            # o SecLists existe mas o arquivo esperado não → tenta o common.txt
            common = os.path.join(root, "Discovery/Web-Content/common.txt")
            if kind == "content" and os.path.isfile(common):
                return WordlistChoice(common, "seclists", kind, size)

    for w in _SYSTEM_FALLBACKS.get(kind, ()):  # 2º melhor: wordlist do SO
        if os.path.isfile(w):
            return WordlistChoice(w, "system", kind, size)

    builtin = _BUILTIN[kind]
    return WordlistChoice(str(builtin), "builtin", kind, size)


def summary_by_profile(kind: str = "content") -> list[str]:
    """Linhas para o ``doctor``: qual wordlist seria usada por perfil."""
    lines = []
    for profile in ("quick", "standard", "deep"):
        choice = resolve(kind, profile)
        flag = " ⚠ reduzida" if choice.reduced_coverage else ""
        lines.append(f"{profile:8} → {choice.source} ({choice.size}){flag}")
    return lines
