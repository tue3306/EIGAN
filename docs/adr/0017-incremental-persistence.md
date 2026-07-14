# ADR-0017 — Persistência incremental + ciclo de vida do scan

- **Status:** aceito
- **Data:** 2026-07-14
- **Relacionado:** CLAUDE.md §11 (dados e findings), ADR-0009 (agente autônomo)

## Contexto

Bug sério de confiabilidade. Os findings eram gravados **só no `_finalize`**
(`CognitiveEngine`, uma única escrita no fim). Se o scan era morto/timeout/crash
(ex.: um scan longo de rede que estoura o tempo), **TODO o trabalho era perdido** —
nada incremental. Um pentest de horas que caísse não deixava rastro.

## Decisão

**Gravação incremental por onda + status de ciclo de vida.**

- **Store** (`findings/store.py`): novas colunas `status`
  (`running | completed | failed | cancelled | partial`) e `executed_capabilities`
  (JSON). `create_scan` nasce `running`; `finish_scan(status=…)` marca o término;
  `set_status`/`set_executed_capabilities`/`get_executed_capabilities`/
  `running_scans()` completam o ciclo. Migração idempotente (bancos antigos com
  `finished_at` viram `completed`).
- **UPSERT** em `add_findings` (`ON CONFLICT(scan_id, fingerprint) DO UPDATE`): a
  onda grava o finding cru; o `_finalize` **regrava por cima** a versão dedupada e
  pontuada (risco). Antes era `INSERT OR IGNORE` — a versão pontuada seria ignorada.
- **Engine**: após cada onda executada, `_persist_incremental` grava as descobertas
  e as capacidades já executadas **na hora** — durável contra kill/timeout. O
  `_finalize` deixa de ser o único ponto de escrita: só consolida/dedupa/pontua. É
  best-effort (uma falha de escrita é logada, nunca derruba o scan).
- **ScanManager**: nos handlers de cancelamento/falha/escopo, marca o status
  persistido (`cancelled`/`failed`) via `finish_scan` — os findings parciais já
  gravados permanecem legíveis (relatório de scan parcial funciona).

## Consequências

- **Positivas:** um scan interrompido **preserva o que já achou** (verificado ao
  vivo: scan morto a 45s manteve o finding + `executed_capabilities`, antes perdia
  tudo). `running_scans()` + `executed_capabilities` dão a **base para retomada**.
  Seguro sob WAL (UPSERT respeita o `UNIQUE(scan_id, fingerprint)`).
- **Custos:** uma escrita por onda (em vez de uma só no fim) — desprezível ante o
  custo de rede das ferramentas.
- **Fora de escopo (roadmap):** **retomada automática** de um scan `running`/
  `partial` reconstruindo o `ScanState` a partir dos findings persistidos e pulando
  as `executed_capabilities` (as primitivas já existem; falta a orquestração). Um
  scan morto por SIGKILL fica em `running` (não dá para setar status no kill) — o
  `running_scans()` o identifica como retomável.
