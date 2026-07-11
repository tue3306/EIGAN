# Roadmap — Plataforma Autônoma de Cyber Security por Agentes de IA

Este documento captura a **visão de destino** do EIGAN: uma plataforma multiagente
orientada a objetivos, event-driven e observável, onde a IA planeja/decide/dirige
a orquestração **dentro** de um envelope de política determinística. É um plano de
**meses**, executado por **Strangler Fig**: o modo autônomo nasce como camada
acima do determinístico existente; nada quebra; o determinístico permanece como
fallback permanente.

> **Princípio de honestidade (§3.6):** abaixo, o que já é **real** está marcado
> ✅; o que é **scaffold/roadmap** está marcado ⬜ e **não finge funcionar**. Cada
> fase entregue vira ADR + testes + `doctor` refletindo o estado + CHANGELOG.

## Estado atual (real, entregue)

- ✅ **Núcleo cognitivo goal-driven** (ADR-0007/0009): `AgenticPlanner` — a IA
  planeja + replaneja por onda, grounded no registry, com fallback determinístico
  e piso de cascata. Timeline de raciocínio em tempo real na UI.
- ✅ **Policy/Guardrail Engine — Fase 0** (ADR-0011): `ImpactClass` + `vet()`
  determinístico (execute/HITL/reject), testado como policy-as-code. `impact_class`
  no `metadata.yaml` e no `doctor`.
- ✅ **AI Providers modular** (ADR-0010): 8 provedores, registro extensível,
  seleção por config; fallback determinístico.
- ✅ **Capabilities + Plugins** com auto-discovery, **Perspective** 1ª classe,
  schema de Finding normalizado, **Risk Engine** (CVSS/EPSS/KEV `UNVERIFIED`),
  correlação, cascata declarativa, memória/diff entre scans, remediação Ansible
  revisável, relatórios HTML/PDF/JSON/CSV/SARIF sem IA, API `/api/v1` + WS + SPA.
- ✅ **Agente Recon real**; Web/Cloud/AD/Exploitation como scaffold honesto.

## Fases planejadas (ainda não implementadas)

| Fase | Entrega | Estado |
|---|---|---|
| 0 | **Policy/Guardrail Engine** (ImpactClass + vet + HITL + teto) | ✅ real (base) |
| 1 | **Event bus + Saga + Observabilidade (OTel)** + audit trail append-only | ⬜ roadmap |
| 2 | **Fila/workers/DB de produção** (RQ→Celery, Postgres+Alembic, Redis, object store) — defaults zero-infra preservados | ⬜ roadmap |
| 3 | **LLMPort com tool-calling** (function-calling) + loop ReAct; `Decision Agent` submete cada tool-call ao `vet()` — a §3.3 é oficialmente invertida com trilha e HITL | ⬜ roadmap |
| 4 | **RAG + Vector DB** (porta `VectorStorePort`, embutido → pgvector/Qdrant) + **Memory Agent** (episódica/semântica/preferência) | ⬜ roadmap |
| 5 | **Agentes reais**: Discovery/Recon/Scanner/Correlation/Vulnerability/AI-Analyst/Report/Dashboard; Blue com conectores; Red (gated) + Purple | ⬜ parcial (Recon real) |
| 6 | **Learning Agent** — ajuste explicável/reversível de seleção/priorização | ⬜ roadmap |
| 7 | **Frontend com build** (React/Vite), **AuthN/AuthZ (OIDC+RBAC)**, multi-tenant, Helm/K8s | ⬜ roadmap |
| 8 | **Marketplace** de conectores (manifesto assinado, sandbox) — doc-first | ⬜ roadmap |

## Arquitetura de destino (referência)

```
Interfaces (Dashboard/API v2/CLI/Wizard/ChatOps)
  → Agentes (Orchestrator·Planning·Decision·Discovery·Recon·Scanner·Correlation·
             Vulnerability·AI-Analyst·Report·Dashboard·Plugin·Update·Knowledge·
             Memory·Learning·Blue·Red[gated]·Purple) — comunicam por event bus
    → POLICY / GUARDRAIL ENGINE (determinístico, inviolável) ← toda ação passa aqui
      → Execução (Tool Runtime seguro / sandbox por container)
        → Plataforma (Fila·Workers·Postgres·Redis·Vector DB·Object store·Feeds·OTel)
```

**Invariante mestre:** nenhuma ação ativa toca a rede sem passar pelo Policy
Engine. A IA propõe; a política dispõe; o runtime executa; tudo auditado com
`trace_id`/`run_id`/`engagement_id`.

## Especificação dos agentes

Cada agente é um serviço de responsabilidade única (domínio puro + portas),
comunicando por mensagens, idempotente por `(run_id, step_id)`. A especificação
viva (responsabilidade · entradas · saídas · ferramentas · fluxo · regras de
decisão · erros) de Orchestrator, Planning, Decision, Discovery, Recon, Scanner,
Correlation, Vulnerability, AI-Analyst, Report, Dashboard, Plugin, Update,
Knowledge, Memory, Learning, Blue, Red e Purple vive em `docs/agents/` (a ser
preenchida por agente conforme cada um sai de scaffold para real).

## Melhorias propostas (avaliar com ADR)

Policy-as-code testável (✅ base entregue) · digital twin do alvo (grafo
persistente) · attack-path scoring até "crown jewels" · replay de runs a partir da
trilha · evals contínuas da IA · **guardrails de prompt-injection** (saída de
ferramenta é dado não-confiável, nunca instrução ao LLM) · custo/token budget por
engajamento · assinatura criptográfica de relatórios/manifests · dry-run explicável
(✅ via `eigan plan --dry-run`) · feedback humano 👍/👎 first-class p/ o Learning.
