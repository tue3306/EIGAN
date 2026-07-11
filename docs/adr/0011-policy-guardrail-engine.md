# ADR-0011 — Policy / Guardrail Engine (o freio determinístico da autonomia)

- **Status:** aceito (Fase 0 da plataforma autônoma)
- **Data:** 2026-07-11
- **Relacionado:** ADR-0009 (agente autônomo), CLAUDE.md §2/§4,
  `docs/roadmap/autonomous-platform.md`

## Contexto

A visão de plataforma autônoma (a IA planeja, decide, seleciona ferramentas e
dirige a orquestração) só é **responsável** se houver um envelope determinístico
que arbitre cada ação **antes** de ela tocar a rede. Sem isso, autonomia vira uma
ferramenta perigosa. Este é o **pré-requisito** de qualquer poder dado à IA
(precede o tool-calling da Fase 3): a política existe e é testada primeiro.

## Decisão

Um **Policy Engine determinístico e inviolável** (`policy/`):

- **`ImpactClass`** (conceito de 1ª classe, §4.1): `passive` → `active_safe` →
  `active_intrusive` → `exploit_validation` → `state_changing`. Toda
  capacidade/ferramenta declara a sua (`impact_class` no `metadata.yaml`; default
  conservador `active_safe`).
- **`PolicyEngine.vet(ProposedAction) → PolicyDecision`** com veredito
  `EXECUTE | NEEDS_APPROVAL (HITL) | REJECT`, na ordem (a 1ª que casar vence):
  1. **Escopo/autorização** (trava dura, `Scope.enforce`): fora do escopo ⇒ REJECT.
  2. **`STATE_CHANGING`**: proibido por padrão (nunca altera terceiros) ⇒ REJECT.
  3. **`EXPLOIT_VALIDATION`**: exige `allow_exploit` **e** aprovação humana (HITL).
  4. **Acima do teto autônomo** do perfil (`auto_approve_ceiling`) ⇒ NEEDS_APPROVAL.
  5. Caso contrário ⇒ EXECUTE.
- Cada decisão é **auditável** (proposta → veredito → motivo logado).

**Invariante mestre:** nenhuma ação ativa toca a rede sem passar por `vet()`. A IA
propõe; a política dispõe; o runtime executa. A autonomia da IA acontece *dentro*
do envelope — a IA **não pode contorná-lo** (é código determinístico, não prompt).

## Alternativas consideradas

- *Regras espalhadas por `if` no fluxo* — rejeitado: não auditável, não testável
  isoladamente, fácil de furar. O motor centralizado é policy-as-code.
- *Deixar o LLM decidir a destrutividade* — rejeitado (§3.1/§4): decisão de
  segurança nunca depende de IA.

## Consequências

- **Fase 0 entregue e testada** (`tests/test_policy.py`): recusa fora de escopo,
  HITL em exploit, `STATE_CHANGING` proibido, teto por perfil, escopo antes da classe.
- **Integração viva:** `metadata.impact_class` + exibição no `doctor`. A ligação
  ao **loop de execução** (o `Decision Agent` submetendo cada tool-call ao `vet()`)
  é a **Fase 3** do roadmap — declarada honestamente, ainda não no caminho quente.
- Fila de **aprovações HITL** na API/dashboard: roadmap (Fase 7).

## Como validar

```bash
pytest tests/test_policy.py     # policy-as-code: os vereditos determinísticos
eigan doctor                    # ferramentas mostram ⟨impact_class⟩ e o que exige HITL
```
