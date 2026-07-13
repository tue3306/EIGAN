"""Intensidade de scan — traduz perfil + perspectiva em OPÇÕES de ferramenta.

O engine cognitivo passa estas opções (rate, timing do nmap, stealth, portas,
severidade do nuclei, profundidade do crawl) para os runners como ``tool_opts``.
Cada runner usa o que entende e ignora o resto (``**_``) — assim a MESMA capacidade
roda "furtiva", "equilibrada" ou "agressiva" conforme o objetivo, sem espalhar
``if`` de perfil pelos runners (o pedido de autonomia: a ferramenta usa as melhores
opções para o contexto, incluindo evasão de firewall).

Módulo puro (só domínio) — testável isoladamente.
"""

from __future__ import annotations

from ..perspective import Perspective

# Perfis de intensidade. ``timing`` é o -T do nmap (0=paranoid … 5=insane).
# ``stealth`` liga evasão (fragmentação/scan-delay). ``all_ports`` faz varredura
# completa (65535). ``severity`` filtra o nuclei (None = todas). ``depth`` é do crawl.
_INTENSITY: dict[str, dict] = {
    # rápido: só o essencial, alto throughput, severidades que importam.
    "quick": {
        "timing": 4,
        "rate_web": 150,
        "port_rate": 1000,
        "all_ports": False,
        "severity": "critical,high,medium",
        "depth": 1,
        "stealth": False,
    },
    # padrão: equilíbrio esforço × ruído; roda tudo do nuclei.
    "standard": {
        "timing": 4,
        "rate_web": 200,
        "port_rate": 1000,
        "all_ports": False,
        "severity": None,
        "depth": 2,
        "stealth": False,
    },
    # profundo: máximo esforço — todas as portas, crawl mais fundo, sem filtro.
    "deep": {
        "timing": 4,
        "rate_web": 300,
        "port_rate": 2000,
        "all_ports": True,
        "severity": None,
        "depth": 3,
        "stealth": False,
    },
    # furtivo: baixo e devagar para não disparar WAF/IDS (evasão de firewall).
    "stealth": {
        "timing": 2,
        "rate_web": 30,
        "port_rate": 100,
        "all_ports": False,
        "severity": "critical,high",
        "depth": 1,
        "stealth": True,
    },
}

# Aliases de perfil vindos da UI/CLI → perfil de intensidade interno.
_ALIASES = {
    "web-only": "standard",
    "network-only": "standard",
    "ai": "standard",  # "deixe a IA decidir": intensidade padrão, IA orquestra por cima
}


def _profile_key(profile: str) -> str:
    p = (profile or "standard").strip().lower()
    return _ALIASES.get(p, p if p in _INTENSITY else "standard")


def tool_options(profile: str, perspective: Perspective) -> dict:
    """Opções normalizadas de ferramenta para ``profile`` × ``perspective``.

    A perspectiva ajusta o rate: EXTERNAL é conservador (não derrubar produção
    exposta); INTERNAL/UNIFIED podem ser mais agressivos. Furtivo vence tudo.
    """
    base = dict(_INTENSITY[_profile_key(profile)])
    if perspective is Perspective.EXTERNAL and not base["stealth"]:
        # externo exposto: segura um pouco o rate por padrão (respeita a produção).
        base["rate_web"] = min(base["rate_web"], 150)
        base["port_rate"] = min(base["port_rate"], 500)
    return {
        "rate_limit": base["rate_web"],  # tools web (httpx/nuclei/katana/ffuf)
        "port_rate": base["port_rate"],  # naabu
        "timing": base["timing"],  # nmap -T
        "stealth": base["stealth"],  # nmap evasão
        "all_ports": base["all_ports"],  # nmap/naabu
        "severity": base["severity"],  # nuclei
        "depth": base["depth"],  # katana
    }
