# ADR-0018 — Expansão de alvos dirigida por descoberta

- **Status:** aceito
- **Data:** 2026-07-14
- **Relacionado:** CLAUDE.md §3.1 (anti-invenção), §3.2/§3.3 (escopo inviolável),
  ADR-0009 (agente autônomo), ADR-0004 (cascata), ADR-0017 (persistência)

## Contexto

Furo central de lógica de um agente de pentest. O `CognitiveEngine` só escaneava
os alvos **originais**: `_execute_step` fazia `for target in goal.targets`. Os
subdomínios (subfinder/amass), IPs resolvidos (dnsx) e hosts vivos (nmap/naabu)
viravam findings, mas **nunca eram escaneados**. A cascata acrescenta *capacidades*,
nunca *alvos*. Resultado: o subfinder achava `sub.empresa.com`, o dnsx resolvia um
IP, e o engine jamais porta-scaneava esse host/IP.

## Decisão

**Working-set de alvos que cresce com a descoberta**, cercado por invariantes.

- O engine mantém um `working_targets` (lista) + `working_hosts` (set p/ dedup),
  iniciado com os alvos originais (normalizados por host). `_execute_step` escaneia
  o **working-set atual**, não `goal.targets`.
- Após cada onda, `_expand_targets` extrai o host de cada finding (`extract_host` do
  `affected_asset` — só o que a ferramenta REALMENTE reportou, §3.1) e o admite como
  novo alvo se, e só se:
  1. **passa pelo gate de escopo** (`scope.enforce`) ANTES de escanear — perspectiva,
     bloqueio de metadata-SSRF (ADR-0015) e, na trava dura, pertencimento; fora do
     escopo é **descartado** e logado (defesa em profundidade, §3.2/§3.3);
  2. **não é duplicado** (dedup por host contra o working-set);
  3. **cabe no teto duro** `Budget.max_targets` (default 64) — anti-explosão.
- Cada admissão/descarte é **auditável na timeline** (`[expansão] novo alvo: X ← Y`
  / `... FORA de escopo, descartado`). Os descobertos entram no `ScanState` e no
  `CognitiveReport.discovered_targets`.

## Consequências

- **Positivas:** o agente agora escaneia o que a recon descobre (subdomínio→IP→
  portas→web→segredos), fechando o furo central. Provado por teste de integração
  (`test_target_expansion_scans_discovered_subdomain`: o subdomínio do subfinder é
  escaneado pelo naabu). Escopo e teto invioláveis (testes de corte por escopo e cap).
- **Custos:** o working-set pode incluir hostname E o IP resolvido (scan de ambos) —
  correto num pentest, limitado pelo teto.
- **Fora de escopo (roadmap):** **priorização por IA** de QUAIS descobertos aprofundar
  primeiro (hoje a admissão é determinística/FIFO sob o teto — segura e completa; a
  IA já decide as capacidades); reverse-DNS/PTR dos IPs como fonte de novos hostnames
  (ADR de profundidade de DNS).
