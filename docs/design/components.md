# Componentes da interface web

A SPA (`src/eigan/api/static/`) é JavaScript vanilla sem build step
(ver [ADR-0004](../adr/0004-cascade-orchestration-and-web-ui.md)). Componentes são
funções puras que recebem dados e retornam HTML; **zero regra de negócio** — tudo
vem de `/api/v1`.

## Arquivos

| Arquivo | Papel |
|---|---|
| `index.html` | Shell: header, navbar, `<div id="view">`, carrega CSS/JS |
| `styles.css` | Design system: tokens (cores/severidade/espaçamento), tema claro/escuro, componentes visuais |
| `app.js` | Roteador por hash, helpers de API, componentes e views |

## Design system (tokens)

Definidos em `:root` de `styles.css` e reutilizados por tudo:

- Cores: `--bg --panel --border --fg --muted --accent --accent2`.
- Severidade: `--crit --high --med --low --info` + classes `.s-<sev>` / `.pill`.
- Layout: `--radius --gap`; utilitários `.card .grid .cols .row .between`.
- Tema claro via `@media (prefers-color-scheme: light)`.

## Componentes reutilizáveis (`app.js`)

| Componente | Assinatura | Uso |
|---|---|---|
| `sevPill(sev)` | severidade → badge colorido | tabelas, feed |
| `kpiCard(v, label)` | número + rótulo | painel, detalhe |
| `kevCell(risk)` | risco → KEV/`UNVERIFIED` | tabela de findings |
| `scanCard(scan)` | scan → linha de tabela clicável | painel, histórico |
| `toast(msg)` | notificação efêmera | feedback de ação |
| `esc(s)` | escape HTML (anti-XSS) | toda renderização de dado |

## Views (roteadas por hash)

| Rota | View | Fonte de dados |
|---|---|---|
| `#/` | `viewDashboard` | `/stats`, `/scans`, `/assets` |
| `#/new` | `viewWizard` (5 passos) | `POST /scans` ao final |
| `#/job/{id}` | `viewProgress` (WebSocket) | `/ws/scans/{id}/progress` |
| `#/scan/{id}` | `viewScanDetail` | `/scans/{id}/findings|inventory|attack` |
| `#/scans` | `viewHistory` | `/scans` |

## Requisitos não-funcionais

- **Acessível:** contraste em ambos os temas, foco visível, semântica de tabela.
- **Anti-XSS:** todo dado passa por `esc()` antes de ir ao DOM.
- **Responsivo:** grids colapsam < 760px; tabelas com scroll horizontal.
- **Resiliente:** WebSocket cai → polling automático; erros mostram mensagem
  acionável, não tela branca.

## Como estender (novo módulo = novo componente)

1. Adicione um componente-função em `app.js` (recebe dados, devolve HTML).
2. Se for uma tela nova, registre uma rota em `ROUTES` e escreva a `view`.
3. Consuma um endpoint existente ou adicione um em `api/app.py` — **nunca**
   coloque regra de negócio no frontend.
