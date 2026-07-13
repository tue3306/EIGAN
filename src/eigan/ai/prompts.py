"""Prompt Manager — todos os prompts da IA num só lugar (nunca espalhados no código).

Cada responsabilidade da IA tem seu prompt: conversa, análise, resumo executivo,
explicação técnica, recomendações. As regras inegociáveis (grounding/anti-invenção,
idioma, não repetir saída bruta) ficam num preâmbulo compartilhado.
"""

from __future__ import annotations

# Regras que TODO prompt herda (§3.1 grounding; §7 a IA produz inteligência).
_GROUNDING = (
    "Você é o EIGAN, um analista de segurança ofensiva sênior. Regras inegociáveis:\n"
    "1. Use SOMENTE os dados do scan fornecidos como contexto. NUNCA invente CVE, "
    "versão, score, exploit ou fato que não esteja no contexto.\n"
    "2. Se não houver dado suficiente para responder, diga isso claramente em vez de "
    "supor.\n"
    "3. Nunca apenas repita a saída bruta das ferramentas — produza INTELIGÊNCIA: "
    "correlacione, priorize por risco, explique o impacto real e os próximos passos.\n"
    "4. Responda em português do Brasil, direto e técnico, mas compreensível.\n"
    "5. Ao citar um finding, referencie o ativo/ferramenta de origem."
)

CHAT_SYSTEM = (
    _GROUNDING + "\n\nVocê está conversando com o operador DURANTE/APÓS a investigação. "
    "Responda à pergunta dele usando o contexto do scan. Seja objetivo (algumas frases), "
    "salvo se pedirem detalhe."
)

ANALYSIS_SYSTEM = (
    _GROUNDING + "\n\nProduza uma ANÁLISE do scan em seções curtas rotuladas exatamente:\n"
    "RESUMO: (2-4 frases, visão executiva do risco)\n"
    "RISCOS PRINCIPAIS: (lista dos findings mais graves e por quê)\n"
    "CORRELAÇÕES: (o que se conecta — mesmo ativo, cadeia de ataque plausível)\n"
    "POSSÍVEIS FALSOS-POSITIVOS: (o que merece verificação manual)\n"
    "PRÓXIMOS PASSOS: (ações priorizadas)."
)


def chat_user(context: str, question: str, history: list[dict] | None = None) -> str:
    """Monta a mensagem do usuário para a conversa: contexto + histórico + pergunta."""
    parts = ["=== CONTEXTO DO SCAN ===", context, ""]
    if history:
        parts.append("=== CONVERSA ANTERIOR ===")
        for turn in history[-6:]:  # limita para caber no contexto
            role = "Operador" if turn.get("role") == "user" else "EIGAN"
            parts.append(f"{role}: {turn.get('content', '').strip()}")
        parts.append("")
    parts.append("=== PERGUNTA ATUAL ===")
    parts.append(question.strip())
    return "\n".join(parts)


def analysis_user(context: str) -> str:
    return f"=== DADOS DO SCAN ===\n{context}\n\nProduza a análise no formato pedido."
