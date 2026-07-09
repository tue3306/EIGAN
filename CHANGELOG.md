# Changelog

Todas as mudanças notáveis do VulnForge são documentadas aqui.

O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o
projeto adota o [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Unreleased]

## [0.2.0] - 2026-07-09

Transformação de "um scanner" em **plataforma modular de operações de segurança**
(Red/Blue/Purple), AI-native e AI-opcional.

### Added
- **Arquitetura de plugins orientada a capabilities** com auto-discovery por
  `metadata.yaml`: adicionar ferramenta não toca o Core (ADR-0001/0003).
- **Perspectiva (Outside-In / Inside-Out)** como conceito de 1ª classe, dirigindo
  guardrails, ferramentas e rate limit por configuração.
- **Risk Engine** (CVSS v3.1/v4, EPSS, CISA KEV) e **Correlation Engine** por
  ativo, com sinais não confirmados marcados `UNVERIFIED` (fonte oficial —
  ADR-0002).
- **MVP Red/Blue/Purple:** Red (subfinder, dnsx, naabu, nmap, httpx, nuclei);
  Blue (inventário, conformidade indicativa, postura de risco); Purple (mapa
  MITRE ATT&CK + gap analysis + relatório executivo).
- **14 módulos scaffolded honestos** (AD, Cloud, Wireless, SIEM, Threat Hunting,
  Attack Simulation, …): contrato declarado, ainda não executam.
- **Relatórios** Técnico e Executivo em **HTML, PDF, JSON, CSV e SARIF** — todos
  funcionam sem IA.
- **CLI "baixa e roda":** wizard interativo, `vulnforge doctor`, consent gate
  inline, padrões zero-config, `.env.example`, `vulnforge feeds update`.
- **API REST versionada** (`/api/v1`) + **dashboard web** via `vulnforge serve`
  (KPIs, severidade, cobertura ATT&CK, inventário).
- **Camada de IA** multi-provedor (Anthropic/OpenAI/Google/Ollama) com **fallback
  determinístico** e grounding obrigatório; toda saída marcada `ai_generated`.
- **Design system** documentado (tokens, claro/escuro), **landing page** estática
  e **logo/favicon** (SVG).
- **Documentação e comunidade:** README task-first, `docs/` (architecture, ADRs,
  design, roadmap), `CONTRIBUTING`, `CODE_OF_CONDUCT`, `SECURITY`, templates de
  Issue/PR e este changelog.

### Changed
- `CLAUDE.md` reescrito para a realidade VulnForge: autonomia concedida,
  AI-native/AI-opcional, plugins/capabilities e "baixa e roda" como requisito.

### Security
- Guardrail de escopo + consent gate bloqueiam alvos não autorizados por padrão;
  travas público/privado por perspectiva; subprocess seguro (lista de args, sem
  `shell=True`).

## [0.1.0] - 2026-07-08

### Added
- Fundação: guardrail de escopo + consent gate, schema de finding normalizado,
  store SQLite (Repository Pattern), `BaseToolAdapter` + adapters nmap/nuclei,
  orquestrador com dedup, base de conhecimento (skills), relatório determinístico
  HTML/PDF, camada de IA com porta de fallback, API REST + esqueleto de dashboard,
  CLI headless com `--fail-on`.

[Unreleased]: https://github.com/tue3306/vulnerability-scanner/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/tue3306/vulnerability-scanner/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tue3306/vulnerability-scanner/releases/tag/v0.1.0
