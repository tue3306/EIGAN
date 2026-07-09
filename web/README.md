# web/ — Landing page e identidade visual

Site estático (landing) e os **assets de marca / design tokens** do VulnForge.
Zero regra de negócio aqui (CLAUDE.md §10) — apenas apresentação.

## Conteúdo

- **`index.html`** — landing page (hero, sobre, funcionalidades, prévia do
  dashboard, arquitetura, comparação verificável, roadmap, FAQ, contato, aviso
  legal). Self-contained, responsiva e com suporte a claro/escuro.
- **`assets/tokens.css`** — **fonte única** dos design tokens (cores,
  severidades, tipografia, espaçamento). Consumido pela landing; documentado em
  [../docs/design/README.md](../docs/design/README.md).
- **`assets/logo.svg`** — logo adaptável (claro/escuro via `prefers-color-scheme`);
  `logo-light.svg` / `logo-dark.svg` para fundos fixos; `favicon.svg` (símbolo).

## Ver localmente

Abra `web/index.html` no navegador, ou sirva a pasta:

```bash
python -m http.server -d web 5500   # http://127.0.0.1:5500
```

> O **dashboard da aplicação** (diferente desta landing) sobe com
> `vulnforge serve` e vive em `src/vulnforge/api/static/`. Ambos compartilham a
> mesma identidade visual definida em `tokens.css`.
