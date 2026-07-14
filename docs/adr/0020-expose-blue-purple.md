# ADR-0020 — Blue e Purple como cidadãos de 1ª classe (menu · CLI · API)

- **Status:** aceito
- **Data:** 2026-07-14
- **Relacionado:** CLAUDE.md §5, §18 (o usuário final não toca a CLI), ADR-0014 (auth)

## Contexto

Blue e Purple existiam mas não estavam acessíveis pelo produto: o menu interativo
era Red-only (apesar do banner "Red·Blue·Purple"), não havia `eigan purple` (só a
API), nem `POST /blue` nem UI web para lançar Blue.

## Decisão

- **Menu** (`cli/menu.py`): novas opções **"Análise Blue (logs)"** e **"Correlação
  Purple"** (`action_blue`/`action_purple`), com renumeração (Sair→9).
- **CLI**: novo comando **`eigan purple <scan_ids...> [--ai]`** — correlaciona os
  scans (Red×Blue), mostra a % de cobertura e os PONTOS CEGOS; `--ai` narra a
  priorização (exige provedor).
- **API**: **`POST /api/v1/blue`** — recebe o **conteúdo** dos logs (upload por
  corpo JSON), não um caminho no servidor. SEGURANÇA (§4/§5): **nunca** lê o
  filesystem do servidor por caminho arbitrário; o conteúdo é gravado num tempdir
  isolado, analisado e apagado; nome de arquivo saneado (basename). Auth (ADR-0014)
  e o gate AI-native preservados (428 sem provedor quando `ai=true`).

## Consequências

- **Positivas:** Blue e Purple deixam de ser CLI/API-only escondidos; o menu reflete
  o banner; a web lança Blue sem expor o FS (decisão de upload-por-conteúdo em vez
  de path). Testado: endpoint (202/401/detecção T1110), CLI purple (cobertura/gaps).
- **Custos:** o `POST /blue` carrega o conteúdo do log no corpo (teto de 8 MB/arquivo,
  20 arquivos) — suficiente para logs típicos; logs enormes ficam para a CLI.
- **Fora de escopo (roadmap):** view dedicada no dashboard para lançar Blue por
  upload e ver Purple sem sair da web (o endpoint já habilita); `POST /purple` já
  existia (mantido).
