# docs/ — Documentação do EIGAN

Índice da documentação técnica e de produto.

## Arquitetura e decisões
- [architecture.md](architecture.md) — camadas, schema de finding, perspectiva,
  núcleo cognitivo (AI-native), pipeline.
- [adr/](adr/) — Architecture Decision Records (o *porquê* das decisões):
  - [0001](adr/0001-plugin-capability-architecture.md) — arquitetura de plugins/capabilities
  - [0002](adr/0002-risk-engine-feeds.md) — feeds do Risk Engine (EPSS/KEV, fonte oficial)
  - [0003](adr/0003-plugins-directory-layout.md) — layout do diretório de plugins
- [DECISIONS.md](DECISIONS.md) — registro rápido de decisões menores.

## Produto e processo
- [ROADMAP.md](ROADMAP.md) — entregue (MVP), scaffolded e futuro.
- [roadmap/commercial.md](roadmap/commercial.md) — itens comerciais **apenas
  documentados** (sem código).
- [BLOCKERS.md](BLOCKERS.md) — bloqueios reais isolados (não param o resto).
- [internal/](internal/) — notas históricas de planejamento e auditoria
  (retratos de um momento, não são a referência viva).

## Design
- [design/](design/) — design system: tokens, cores/severidades, tipografia,
  componentes, claro/escuro, uso do logo.

## Para desenvolvedores
- Como criar um plugin em ~5 min: [../CONTRIBUTING.md](../CONTRIBUTING.md).
- Contrato de plugin e categorias: [../plugins/README.md](../plugins/README.md).
- API: `eigan serve` expõe `/docs` (OpenAPI) e `/api/v1`.
