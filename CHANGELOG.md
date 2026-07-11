# Changelog

Todas as mudanças notáveis do EIGAN são documentadas aqui.

O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o
projeto adota o [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Unreleased]

### Added
- **Plataforma autônoma — 10 pilares (Missão 4 / ADR-0008)**: contratos entre
  planner ↔ agentes ↔ memória ↔ correlação ↔ reporting ↔ remediação, com o status
  **real × scaffold** de cada pilar declarado no ADR e no `ROADMAP`.
- **Pilar 2 — Memória entre scans (real)**: diff **determinístico**
  (`analysis/diff.py` + `FindingStore.find_previous_scan`) entre dois scans do
  mesmo alvo — novos/corrigidos/persistentes + novos ativos/serviços. CLI
  `eigan diff --scan <id> [--against <id>] [--ai]`; a IA **só narra** (fallback
  determinístico via `summary()`).
- **Pilar 6 — Auto Remediation (real, formato Ansible)**: `report/remediation.py`
  gera **playbooks Ansible revisáveis** a partir do finding (restringir serviço
  exposto via firewall; cabeçalhos de segurança HTTP) — **sugestão, nunca
  aplicada automaticamente**. CLI `eigan remediate --scan <id> --out <dir>`;
  findings sem template são listados honestamente (scaffold), sem fabricar.
- **CI `smoke-install` (Missão 5)**: job que, em ambiente limpo, instala o pacote
  e roda `eigan --version`, `eigan doctor` e `eigan plan … (dry-run)`
  sem erro — valida "baixa e roda".
- **Núcleo Cognitivo goal-driven (Missão 3 / ADR-0007)**: subpacote
  `engine/cognitive/` acima do `Orchestrator`. O usuário informa um **objetivo**
  (`eigan plan <alvo> --goal attack-surface`) e o **Planner** deriva as
  **capacidades**; o **Tool Selection Engine** escolhe a ferramenta de cada
  capacidade de forma determinística e **justificada** (ex.: `naabu` externo vs.
  `nmap` interno para `port_discovery`); os **Agentes** roteiam por especialidade
  (**Recon real**; Web/Cloud/AD/Exploitation *scaffold honesto*, visíveis no
  `doctor`). Loop `Goal → Planner → Seleção → Execução → Feedback → replan →
  Stop`, com replan pela cascata determinística e **rastro auditável** de cada
  decisão. Fronteira garantida por código: a IA (opcional) só **ordena
  capacidades** (ids inventados descartados — §3.1) e tem **fallback
  determinístico**; nunca escolhe ferramenta nem executa. Consent gate/escopo
  como pré-condição da execução real (`--execute`).
- **CLI `eigan plan`** (dry-run por padrão, seguro) e **sinais de seleção**
  (`selection:` em `metadata.yaml`) nos plugins recon. Nova seção **"Agentes
  cognitivos"** no `doctor`.
- **Camada de IA concreta (Missão 2)**: adapters HTTP para **Anthropic, OpenAI,
  Google e Ollama** substituem o placeholder `None` em `ai/provider.py`. Cada um
  faz *grounding* (só finding + skill como contexto), *redaction* de segredos/PII
  antes de sair para provedor externo (Ollama local não redige), marca
  `ai_generated: true` e **cai para o fallback determinístico** em qualquer erro.
  Seleção por ambiente (Anthropic → OpenAI → Google → Ollama): a Anthropic liga
  só com a chave (modelo padrão verificado `claude-opus-4-8`); os demais exigem
  `<PROVIDER>_MODEL` — sem id fabricado (§3.1). Chaves **só via env**.
- **Download de relatório na API**: `GET /api/v1/scans/{id}/report?format=&style=&ai=`
  serve HTML/PDF/JSON/CSV/SARIF como `FileResponse`; PDF **degrada para HTML**
  (header `X-Report-Degraded: pdf->html`), sem stack trace. Botão **⬇ Exportar
  relatório** no detalhe do scan no dashboard (estilo técnico/executivo + formato).
- **`GET /api/v1/setup`** + banner de onboarding no dashboard: mostra o que está
  degradado (IA desligada, PDF indisponível, ferramentas faltando) com o **comando
  exato** para resolver — nada de tela em branco silenciosa.
- **Degradação de PDF ponta-a-ponta**: `render_pdf` e o comando `report` da CLI
  detectam WeasyPrint/libs ausentes e gravam **HTML** com aviso acionável
  (`eigan doctor`), em vez de falhar.

### Changed
- **`config/ai.yaml` e `.env.example`**: refletem os padrões reais — Anthropic com
  `claude-opus-4-8` por padrão e `<PROVIDER>_MODEL` obrigatório para os demais.
- **Landing (`web/index.html`)**: quickstart alinhado ao launcher real
  (`git clone … && python3 eigan.py`).

### Added (Missão 1)
- **Launcher "unzip e um comando" (Missão 1 / ADR-0006)**: `python3 eigan.py`
  agora confere Python ≥ 3.11 (com link oficial por SO), instala `.[pdf,tui]` por
  padrão e prepara diretórios de config. Flags: `--with-tools`, `--with-ai`,
  `--serve`, `--reinstall`, `--no-venv`, `--dev`, `--help`. Aceite medido: **1
  comando** do projeto descompactado ao menu/wizard (Kali, 2026-07-10).
- **`eigan doctor --install`** (+ `python3 eigan.py --with-tools`):
  provisão **consent-gated** das ferramentas com runner real ausentes — lista
  exatamente o que vai rodar antes de confirmar; `nmap` via gerenciador de
  pacotes do SO (lista de args, sem shell), ferramentas ProjectDiscovery apontam
  a fonte oficial + Docker sem fabricar comando/versão (§3.1).
- **Status de PDF no `doctor`** e detecção `report/pdf_support.py`: se as libs do
  WeasyPrint faltarem, o relatório **degrada para HTML** com aviso acionável.
- **`.github/workflows/publish.yml`**: publicação no PyPI via *trusted
  publishing* (OIDC, sem token), disparo em Release — inerte até o dono
  configurar o publisher (ver `docs/BLOCKERS.md` #5).

### Docs
- **ADR-0006** (estratégia de provisão de ferramentas: container × PyPI ×
  `doctor --install`) e `docs/BLOCKERS.md` #4/#5 (executor em container;
  publicação no PyPI).

## [0.3.0] - 2026-07-10

Release **Interface & Experiência de Produto**: o EIGAN deixa de parecer uma
biblioteca Python e passa a "baixar e rodar" com um único comando.

### Added
- **Launcher único `eigan.py` na raiz** (Missão 0 / ADR-0005): só stdlib.
  `git clone && python3 eigan.py` cria `.venv`, instala o pacote (extra
  `[tui]`, com fallback para a base), gera `.env` a partir de `.env.example` e
  abre o menu — sem o usuário conhecer a estrutura do projeto. Atalho `./eigan`.
- **Menu de produto** (`cli/menu.py`): `eigan` sem argumentos abre um menu
  numerado — Novo Scan, Dashboard, Histórico, Configuração, Doctor, Atualizar
  Ferramentas. Camada fina sobre a CLI (nenhuma regra de negócio nova), com
  ações testáveis (`input_fn`/`echo` injetáveis) e resiliente a erro (mensagem
  acionável, nunca stack trace).
- **TUI full-screen (Textual)** (`cli/tui.py`): experiência premium opcional
  (extra `[tui]`) com **fallback determinístico** para o menu numerado quando não
  há Textual ou TTY. Comando `eigan menu` explícito.
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
- `eigan` **sem argumentos** agora abre o **menu** (antes: o wizard direto).
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
- **CLI "baixa e roda":** wizard interativo, `eigan doctor`, consent gate
  inline, padrões zero-config, `.env.example`, `eigan feeds update`.
- **API REST versionada** (`/api/v1`) + **dashboard web** via `eigan serve`
  (KPIs, severidade, cobertura ATT&CK, inventário).
- **Camada de IA** multi-provedor (Anthropic/OpenAI/Google/Ollama) com **fallback
  determinístico** e grounding obrigatório; toda saída marcada `ai_generated`.
- **Design system** documentado (tokens, claro/escuro), **landing page** estática
  e **logo/favicon** (SVG).
- **Documentação e comunidade:** README task-first, `docs/` (architecture, ADRs,
  design, roadmap), `CONTRIBUTING`, `CODE_OF_CONDUCT`, `SECURITY`, templates de
  Issue/PR e este changelog.

### Changed
- `CLAUDE.md` reescrito para a realidade EIGAN: autonomia concedida,
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
