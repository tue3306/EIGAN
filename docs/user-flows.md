# Jornadas do usuário (user flows)

As cinco jornadas principais da interface web. Todas começam em
`eigan serve` → abrir `http://127.0.0.1:8000`. **Nenhuma exige a CLI.**

## 1. Novo scan (a "magia")

1. Clicar **+ Novo Scan** (painel ou navbar).
2. **Passo 1 — Alvo:** IP, range, domínio ou lista (vírgula/espaço).
3. **Passo 2 — Perspectiva:** EXTERNA (Outside-In) ou INTERNA (Inside-Out).
4. **Passo 3 — Objetivo:** Rápido, Padrão (recomendado), Profundo ou "Deixe a IA
   decidir".
5. **Passo 4 — Avançado (colapsável):** orquestração em cascata (ligada por
   padrão), rate limit, modo de validação.
6. **Passo 5 — Confirmação + consentimento:** resumo + caixa obrigatória de
   autorização. Sem marcar, o botão fica desabilitado (`POST /scans` recusaria
   com 403 de qualquer forma — o consent gate é preservado no backend).
7. Iniciar → redireciona para a tela de progresso (job).

Backend: `POST /api/v1/scans` → cria job em thread → `202` com `job_id`.

## 2. Acompanhar progresso em tempo real

- A tela abre um **WebSocket** `/ws/scans/{job_id}/progress` (fallback: polling
  `/progress?since=`).
- Mostra: barra de progresso, **fases** (✅/⏳), **cascata** (cada disparo com
  justificativa e marca "sugerido" quando roadmap) e **feed de descobertas** com
  severidade e "↳ cascata: dispara X".
- Ações: **Cancelar** (cancelamento cooperativo), voltar ao painel.
- Ao concluir, oferece ir ao detalhe do scan persistido.

## 3. Ver histórico de scans

- Navbar **Histórico** ou tabela no painel → lista de scans (`GET /scans`).
- Clicar numa linha abre o **detalhe** do scan.

## 4. Interpretar resultado (detalhe do scan)

- `#/scan/{id}`: KPIs (findings, críticos, altos, técnicas ATT&CK), tabela de
  findings com filtro por severidade (risco, CWE, KEV, perspectiva, fonte) e
  inventário de ativos.
- Dados de `GET /scans/{id}/findings|inventory|attack`.

## 5. Gerar relatório / remediar

- Relatórios Técnico e Executivo em HTML/PDF/JSON/CSV/SARIF via
  `eigan report --scan <id> --format pdf` (ou API de relatório).
- **Exportações (JSON/SARIF/CSV)** são determinísticas e reprodutíveis; as
  **narrativas** (Técnico/Executivo) são geradas pela IA e marcadas `ai_generated`
  (o EIGAN exige um provedor de IA para rodar — ADR-0012).

---

**Resumo:** um usuário não-técnico agora escaneia de ponta a ponta clicando em
botões — alvo → perspectiva → objetivo → autorização → progresso ao vivo →
resultado — sem nunca abrir um terminal.
