# Changelog

Todas as mudanças notáveis do EIGAN são documentadas aqui.

O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o
projeto adota o [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Unreleased]

> ⚠️ **Versão reiniciada para `0.0.0` (pré-alfa).** As tags `1.x` anteriores
> superestimavam a maturidade: o Red team não era comandado pela IA na CLI/wizard,
> o Blue team é só scaffold e não há Purple real, e o dashboard precisa de trabalho.
> O versionamento só volta a subir quando Red **e** Blue **e** Purple rodarem de
> ponta a ponta. Honestidade acima de número de versão (§3.1).

### Fixed (crítico — a IA volta a comandar o Red team)
- **`eigan scan` e o wizard rodavam um pipeline FIXO sem IA.** O `execute_scan`
  exigia um provedor (§3.4) mas depois ignorava a IA e rodava o `Orchestrator`
  determinístico — contrariando §3.4/§7/§18 ("a IA comanda o scan fim a fim").
  Agora `execute_scan` roda o **`CognitiveEngine`** (mesmo motor da API/dashboard):
  a IA planeja as capacidades, reage às descobertas e replaneja em ondas. O
  operador **vê a IA raciocinar** no terminal (plano · seleção · execução).
- **O `AgenticPlanner` caía no determinístico em TODO scan** porque o GPT-5 às vezes
  emite JSON malformado (aspa faltando) e o parse falhava silenciosamente. Novo
  **JSON mode** (`response_format`/`response_mime_type`/`format:json`) em todos os
  provedores (OpenAI/Azure/Gemini/Ollama) força saída estruturada válida; o Planner
  pede `json_mode=True` e tenta 2×. Verificado ao vivo: GPT-5 passou a devolver JSON
  válido e a IA de fato comanda o plano.

### Fixed (dashboard — progresso ao vivo estava quebrado)
- **A barra de progresso travava em 4% e o painel "Fases" ficava vazio** o scan
  inteiro: o dashboard escutava eventos `phase_*` do Orchestrator antigo, mas o
  `CognitiveEngine` (que a API roda) emite `tool_execution`. Agora a barra avança
  a cada ferramenta concluída e o painel mostra as **ferramentas & capacidades**
  reais (subfinder ✅, dnsx ✅, nmap ⏳…). Ao terminar, leva ao detalhe do scan
  mesmo com 0 findings (antes ficava preso na tela de progresso).
- **Percentuais de cobertura inventados** ("~60%/~85%") removidos do wizard web
  (anti-invenção §3.1); a opção enganosa "IA decide" saiu (a IA comanda **todos**
  os perfis) e o wizard passa a dizer isso.

### Added
- **Wizard abre o dashboard direto no scan concluído.** Ao final de um "Novo Scan"
  o assistente oferece subir o dashboard já no deep-link `#/scan/<id>` (fecha a
  lacuna de não haver como ver o resultado na web logo após escanear). `serve_app`
  ganhou o parâmetro `open_path` para o deep-link.
- **Resumo pós-scan por severidade** no wizard: contagem colorida
  `CRÍTICA · ALTA · MÉDIA · BAIXA · INFO` + top findings ordenados por risco (a
  "cara" do ataque encontrado) antes da oferta de relatório.
- Helper de apresentação compartilhado `cli/ui.py` (`boxed`/`rule`): menu, wizard e
  TUI passam a desenhar a **mesma moldura alinhada**.

### Fixed
- **Moldura do cabeçalho do wizard desalinhada** (bordas de larguras diferentes) —
  agora usa a caixa alinhada de `cli/ui.py`.
- **`FindingStore(None)`/`""` criava um banco-fantasma `None`** no disco (`str(None)`
  → `"None"`); agora cai no default seguro `eigan.db`. Artefatos de runtime (`None`,
  `gowitness.jsonl`, sidecars `*.db-wal`/`*.db-shm`) removidos do versionamento e
  ignorados.

### Tests
- +20 testes: `cli/ui.py`, resumo por severidade do wizard, deep-link do
  `serve_app`, parser de `.env` (`envfile`, 0→100% de cobertura) e regressão do
  banco-fantasma `None`.

## Histórico anterior (pré-reset)

As seções `1.2.0`, `1.1.0`, `1.0.x`, `0.3.0`, `0.2.0` e `0.1.0` foram
**removidas** no reset para `0.0.0` (as tags/releases correspondentes também).
Elas superestimavam a maturidade do projeto. O detalhe completo dessas notas
permanece preservado no histórico do git (`git log`, commits até `951fdd6`).

