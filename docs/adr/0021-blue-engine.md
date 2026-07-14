# ADR-0021 — Blue Engine (análise defensiva de logs, caminho separado do cognitivo)

- **Status:** aceito (retroativo — decisão já implementada)
- **Data:** 2026-07-14
- **Relacionado:** CLAUDE.md §16 (ADR do porquê), ADR-0009 (agente cognitivo)

## Contexto

O EIGAN precisava de um Blue team REAL (era 100% scaffold). A análise defensiva
consome **logs** (SSH/PAM, acesso web, sudo), não faz recon ativo — o loop
cognitivo (Goal→Plano→Seleção→Execução em rede) não é o modelo certo para ela.

## Decisão

Um **caminho de execução separado** (`engine/blue.py::run_log_analysis`) que roda o
plugin `log-analysis` (nativo Python) sobre os caminhos de log, normaliza para
`Finding` (com `attack_technique` MITRE mapeado às linhas reais), persiste como um
scan (perspective INTERNAL) e dispara a análise/remediação da IA (mesmo downstream
do Red). Exposto via `eigan blue`, agente `blue-detection` (built) e
`POST /api/v1/blue`. `BlueReport` é parcialmente compatível com `CognitiveReport`
(o relatório/dashboard consomem sem saber a origem).

## Consequências

- **Positivas:** Blue real, no mesmo store/dashboard/relatórios do Red, alimentando
  a correlação Purple ([[0022-purple-correlation]]). Determinístico na detecção; a
  IA só narra/prioriza (§3.1).
- **Fora de escopo (roadmap):** os demais plugins Blue (SIEM/detection-rules/
  threat-hunting/incident-response/malware-analysis) seguem scaffold honesto.
