# Changelog

Todas as mudanças notáveis do VulnForge são documentadas aqui.

O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o
projeto adota o [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Unreleased]

## [0.3.0] - 2026-07-10

Release **Interface & Experiência de Produto**: o VulnForge deixa de parecer uma
biblioteca Python e passa a "baixar e rodar" com um único comando.

### Added
- **Launcher único `vulnforge.py` na raiz** (Missão 0 / ADR-0005): só stdlib.
  `git clone && python3 vulnforge.py` cria `.venv`, instala o pacote (extra
  `[tui]`, com fallback para a base), gera `.env` a partir de `.env.example` e
  abre o menu — sem o usuário conhecer a estrutura do projeto. Atalho `./vulnforge`.
- **Menu de produto** (`cli/menu.py`): `vulnforge` sem argumentos abre um menu
  numerado — Novo Scan, Dashboard, Histórico, Configuração, Doctor, Atualizar
  Ferramentas. Camada fina sobre a CLI (nenhuma regra de negócio nova), com
  ações testáveis (`input_fn`/`echo` injetáveis) e resiliente a erro (mensagem
  acionável, nunca stack trace).
- **TUI full-screen (Textual)** (`cli/tui.py`): experiência premium opcional
  (extra `[tui]`) com **fallback determinístico** para o menu numerado quando não
  há Textual ou TTY. Comando `vulnforge menu` explícito.
- **`serve --open`**: sobe o dashboard e **abre o navegador** automaticamente
  (thread que espera a porta responder); a opção Dashboard do menu usa o mesmo
  caminho.
- **Orquestração em cascata dirigida por descoberta** (ADR-0004): plugins
  declaram `triggers_on` no `metadata.yaml` (ex.: porta 445 → `enum4linux`,
  `cme_smb_recon`). `CascadeGraph` casa de forma determinística e o
  `CascadeOrchestrator` executa a segunda onda pelo runner seguro. Cada disparo é
  **registrado e justificado** ("sem mágica"); ferramentas roadmap aparecem como
  *sugeridas, não executadas*. 10 plugins com regras de cascata.
- **Interface web (SPA, sem build step)**: dashboard com histórico e ativos em
  risco, **wizard de 5 passos** (alvo → perspectiva → objetivo → avançado →
  confirmação com autorização inline) e **tela de progresso em tempo real**
  (fases, descobertas, cascatas justificadas) via WebSocket. Design system em
  CSS com tokens; componentes reutilizáveis.
- **API em tempo real**: `POST /api/v1/scans` (background, consent gate
  preservado — 403 sem autorização), `GET /jobs/{id}/progress`, `cascade-log`,
  `cancel`, `GET /findings`, `GET /assets` e WebSocket
  `/ws/scans/{id}/progress`. Streaming por `EventSink` (porta) + `ScanManager`.

### Changed
- `vulnforge` **sem argumentos** agora abre o **menu** (antes: o wizard direto).
  O wizard segue inteiro como opção 1 (Novo Scan) e via os fluxos de scan.
  Divergência declarada do CLAUDE.md §13/§18 — ver ADR-0005.
- Novo extra opcional `[tui]` (Textual + Rich) no `pyproject.toml`.

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
