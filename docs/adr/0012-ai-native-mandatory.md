# ADR-0012 — EIGAN é AI-native e AI-obrigatória (sem "modo sem IA")

- **Status:** aceito (define a filosofia; migração de código faseada)
- **Data:** 2026-07-11
- **Supera:** a postura AI-opcional de ADR-0009 (§3.4 original: "todo recurso de IA
  tem fallback determinístico")

## Contexto

Decisão de produto do dono: **EIGAN é um agente de IA — a IA é a ferramenta**.
Não é "um scanner que a IA enriquece" com fallback determinístico; é uma
ferramenta cuja proposta de valor (planejar a estratégia, escolher ferramentas,
orquestrar em cascata adaptativa, correlacionar e narrar) **só existe com IA**.
"Sem IA = ferramenta não funciona."

Isto **inverte** o antigo §3.4 do CLAUDE.md ("nenhuma função básica depende de
chave de API"). A mudança está registrada aqui e o `CLAUDE.md` foi reescrito
(§1, §3.4, §7, §12, §13, §17, §18, §19).

## Decisão

1. **IA obrigatória:** rodar um scan exige um provedor de IA configurado
   (Anthropic/OpenAI/Gemini/OpenRouter/Groq/Together/Azure ou **Ollama local**).
   Sem provedor, o EIGAN **recusa** com erro acionável — **não há "modo
   determinístico" que produza um scan**.
2. **Os componentes determinísticos permanecem — como substrato, não como
   fallback.** `ToolSelector`, `CascadeGraph` (piso de segurança), `PolicyEngine`,
   execução segura (lista de args, nunca `shell=True`) continuam existindo: são o
   que a IA **comanda** e o que a **política arbitra**. Não são um caminho que
   substitui a IA.
3. **Linhas vermelhas inalteradas (§4):** autorização/escopo, secure coding,
   redaction, grounding/anti-invenção. A obrigatoriedade da IA **não** relaxa
   nenhuma — o gate de escopo e o Policy Engine continuam sendo a última palavra.
4. **Ollama local** é o caminho para quem quer privacidade/offline sem custo por
   token — mas ainda é "ter um provedor". Não equivale a "rodar sem IA".

## Divergência doc × código (honestidade — §3.6)

Esta ADR define o **alvo**. No estado atual do código:

- Os pontos de entrada ainda **permitem** execução determinística (o
  `DeterministicPlanner`, o `DeterministicEnricher` e ~fallbacks existem, e a
  suíte de testes exercita esses caminhos "sem IA"). Isso **não** foi removido
  nesta iteração: fazê-lo é uma mudança **quebrante** (invalida testes que provam
  operação offline e a garantia de CI hermético).
- **Migração faseada (a fazer):**
  - *Fase 1:* gate de produto — wizard/CLI `run`/API recusam iniciar um scan sem
    provedor configurado (erro acionável), mantendo o motor determinístico como
    substrato interno. Ajustar/rotular os testes de "sem IA" para testes de
    *substrato* (não de "produto sem IA").
  - *Fase 2:* remover o `DeterministicEnricher` como *modo de relatório* (narrativas
    passam a exigir IA), preservando as exportações determinísticas (JSON/SARIF/CSV).
- Até lá, o `CLAUDE.md` é a fonte de verdade da **intenção**; o código é migrado
  sem quebrar os gates (lint/type/test verdes a cada passo).

## Consequências

- **Positiva:** identidade de produto nítida e diferenciada (agente de IA de
  verdade), UX de onboarding que exige o provedor logo no início.
- **Trade-off:** perde-se a garantia "roda 100% offline sem chave". Mitigado por
  **Ollama local** (privacidade/offline sem custo por token).
- **Risco gerido:** a migração é faseada para manter os gates verdes; nada é
  removido de forma destrutiva sem os testes correspondentes acompanharem.

## Como validar (após a migração da Fase 1)

```bash
# sem provedor → recusa acionável (não roda, não stack trace)
env -u ANTHROPIC_API_KEY ... eigan scan example.com   # → "configure um provedor de IA"
# com provedor (ou Ollama local) → o agente planeja e executa
```
