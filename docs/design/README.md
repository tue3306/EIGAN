# EIGAN — Design System

Identidade visual e biblioteca de componentes do EIGAN. Objetivo: transmitir
**profissionalismo e confiança** e manter dashboard, landing page e relatórios
coerentes. A fonte única dos valores é [`web/assets/tokens.css`](../../web/assets/tokens.css);
a lógica de negócio **nunca** vive no componente (CLAUDE.md §10).

## Marca

- **Nome:** EIGAN (uma palavra, "V" e "F" maiúsculos). No wordmark, `Vuln`
  usa a cor de texto e `Forge` usa o gradiente da marca.
- **Símbolo:** hexágono (modularidade/plugins + metal *forjado*) com um "V" que
  também é um *chevron* de análise (drill-down nos findings).
- **Arquivos** (`web/assets/`): `logo.svg` (adaptável claro/escuro via
  `prefers-color-scheme`), `logo-light.svg`, `logo-dark.svg`, `favicon.svg`.
- **Área de proteção:** deixe ao menos a altura do "V" do símbolo como respiro ao
  redor do logo. Não distorça, não recolora o símbolo, não aplique sombra dura.

## Cores (design tokens)

Modo **escuro é o padrão**; o claro é ativado por `@media (prefers-color-scheme: light)`.

| Token | Escuro | Claro | Uso |
|---|---|---|---|
| `--bg` | `#0b1220` | `#f4f6fb` | fundo da página |
| `--panel` | `#131c2e` | `#ffffff` | cards, header, tabelas |
| `--panel-2` | `#0f1728` | `#eef2f9` | inputs, superfícies aninhadas |
| `--border` | `#24304a` | `#dde3ee` | divisórias, contornos |
| `--fg` | `#e6ecf5` | `#16202e` | texto principal |
| `--muted` | `#8ea0bd` | `#5b6b85` | texto secundário, rótulos |
| `--accent` | `#4f8cff` | — | ação primária, links |
| `--accent-2` | `#6c5ce7` | — | Purple Team, gradiente da marca |

### Severidade (não decorativo — semântico)

Bandas alinhadas às faixas de CVSS. Use **sempre** estes tokens para comunicar
severidade; nunca reuse a cor de severidade para enfeite.

| Severidade | Token | Cor |
|---|---|---|
| Crítica | `--sev-critical` | `#ff4d4f` |
| Alta | `--sev-high` | `#ff7a45` |
| Média | `--sev-medium` | `#ffc53d` |
| Baixa | `--sev-low` | `#73d13d` |
| Info | `--sev-info` | `#8c9bb5` |

Sinais **`UNVERIFIED`** (EPSS/KEV não confirmados) usam `--muted` em itálico —
nunca uma cor de severidade, para não sugerir certeza que não existe.

## Tipografia

- **Família:** `system-ui` stack (`--font-sans`) — zero download, legível em
  Linux/Windows/macOS. Código e ativos em `--font-mono`.
- **Escala:** `--fs-xs` 11 · `--fs-sm` 13 · `--fs-base` 14 · `--fs-lg` 18 ·
  `--fs-xl` 24 · `--fs-2xl` 30 · `--fs-3xl` 44 (px).
- **Pesos:** 400 (corpo), 600 (rótulos/th), 700 (KPIs, logo, títulos). Títulos de
  seção usam `--muted`, uppercase, `letter-spacing` leve.

## Ícones

Conjunto [Lucide](https://lucide.dev) (ISC, uso comercial ok — `# VERIFICAR` a
licença ao fixar versão). Traço coeso, alinhado à grade. **Não** empacotamos a
fonte de ícones no Core: são referenciados/inlined onde usados.

## Componentes

Biblioteca mínima e reutilizável (implementada no dashboard `src/eigan/api/static/`
e na landing `web/`):

- **Card** — `--panel`, borda `--border`, `--radius`, padding `--sp-4`.
- **KPI tile** — número em `--fs-2xl`/700 + rótulo `--muted`.
- **Badge de severidade (pill)** — `--radius-pill`, fundo = token da severidade.
- **Badge de IA** — gradiente da marca; **só aparece quando há provedor ativo**
  (degrada honestamente sem chave).
- **Badge `KEV` / `UNVERIFIED`** — KEV em `--sev-critical`; UNVERIFIED em `--muted`.
- **Barra de distribuição** — largura proporcional, cor = severidade.
- **Tabela** — cabeçalho `--muted`/600, linhas com borda inferior, `overflow-x`
  em wrapper para caber em telas estreitas.
- **Botão / select** — `--panel-2`, borda `--border`, `--radius-sm`.

## Claro/escuro e acessibilidade

- Estratégia: **um conjunto de tokens**, trocado por `prefers-color-scheme`.
  Nenhum componente hardcoda cor — todos leem `var(--token)`.
- Contraste alvo: **WCAG AA** para texto (≥ 4.5:1 corpo, ≥ 3:1 texto grande).
  Pílulas de severitade clara (média/baixa) usam texto escuro; críticas/altas,
  texto branco.
- Responsivo: grids `auto-fit`/`minmax`; conteúdo largo (tabelas) rola no próprio
  contêiner, a página nunca rola na horizontal.

## Como aplicar

Importe os tokens e leia as variáveis:

```html
<link rel="stylesheet" href="/assets/tokens.css">
<style>
  .card { background: var(--panel); border: 1px solid var(--border);
          border-radius: var(--radius); }
  .pill.critical { background: var(--sev-critical); color:#fff; }
</style>
```
