# Arquitetura do EIGAN

## Visão em camadas

```
Interfaces:  CLI (Click, headless/CI)  |  API REST + WS (FastAPI)  |  Dashboard
        │
Aplicação:   Orchestrator (jobs, perfis, dedup)  ·  Enricher (IA/fallback)
        │
Domínio:     Finding (schema)  ·  Scope/Consent (guardrail)   ← sem I/O
        │
Infra:       adapters de ferramenta  ·  FindingStore (SQLite)  ·  ReportGenerator
             ·  KnowledgeBase (skills)  ·  AIProvider (multi-provedor)
```

As dependências apontam para dentro: o domínio (`findings/schema.py`,
`security/scope.py`) não conhece banco, rede nem ferramentas. Adapters, store,
report e IA implementam/consomem esse núcleo.

## Decisões de stack (justificativa)

- **Pydantic v2 para o schema de finding:** validação declarativa + serialização
  JSON estável para o store e a API, com o `fingerprint` derivado no domínio.
- **SQLite via `sqlite3` da stdlib:** zero dependência para o default; o
  `FindingStore` é a porta — trocar por Postgres/SQLAlchemy é uma nova
  implementação, sem tocar em domínio (Repository Pattern).
- **Click no lugar de Typer:** disponível sem instalação adicional e suficiente
  para o CLI headless/CI; Typer permanece como evolução compatível.
- **WeasyPrint (HTML→PDF):** o mesmo template Jinja2 serve HTML e PDF; PDF é
  dependência opcional (`[pdf]`), o HTML sempre funciona.
- **FastAPI:** REST versionado (`/api/v1`) + WebSocket para progresso; fonte
  única de dados para qualquer frontend (nenhuma regra de negócio no cliente).
- **Dashboard server-rendered mínimo primeiro:** entrega valor sem build de
  frontend; a UI React+Vite consome os mesmos endpoints numa fase seguinte.

## Schema de finding

Campos: `title, severity, affected_asset, source_tool, cvss(+version), cwe,
owasp, attack_technique, description, evidence, reproduction, references[],
confidence, status, ai_generated, first_seen, last_seen, correlated_sources[]`.
`fingerprint = sha256(cwe|asset)[:16]` — base da dedup/correlação entre
ferramentas.

## Perspectiva (vantage point)

`Perspective` (`src/eigan/perspective.py`) é um conceito de primeira classe
do domínio que muda o comportamento de todo o pipeline, dirigido por
**configuração** (o mapa `_PROFILES`), não por `if` espalhado:

| Dimensão | EXTERNAL | INTERNAL |
|---|---|---|
| Alvos permitidos | público/hostname; bloqueia RFC1918/loopback/link-local | privado/loopback/hostname; bloqueia IP público |
| Rate limit padrão | 150 (conservador) | 1000 (agressivo permitido) |
| Credenciais | não | opcionais (scan autenticado) |
| OSINT subdomínio | sim (subfinder/amass) | não (já se está dentro) |

Onde toca cada camada:
- **Guardrail** (`security/scope.py`): `enforce()` valida `alvo × perspectiva`
  (público×privado) **antes** de qualquer execução; incompatibilidade levanta
  `PerspectiveViolation`. `override` libera só a regra público×privado (logado),
  nunca a autorização nem o pertencimento ao escopo.
- **Adapter** (`engine/base.py`): declara `supported_perspectives`; o
  orquestrador só ativa adapters compatíveis (ex.: `subfinder` só EXTERNAL).
- **Pipeline** (`engine/pipeline.py`): grafo de estágios por perspectiva; o
  perfil restringe quais estágios rodam; ferramentas de um estágio rodam em
  paralelo; ferramenta ausente/faltando adapter é pulada sem derrubar o fluxo.
- **Finding** (`findings/schema.py`): campo `perspective` entra no `fingerprint`
  — findings de perspectivas diferentes **não** são fundidos. A correlação
  entre perspectivas para o mesmo ativo é feita por `dedup.correlate_by_asset`,
  preservando a origem.

Próximo incremento do pipeline: encaminhamento dinâmico de assets entre estágios
(subfinder → dnsx → naabu → httpx), re-aplicando o guardrail de escopo aos
assets descobertos. Perspectivas reservadas (`ASSUMED_BREACH`, `AUTHENTICATED`)
são extensões futuras do enum + `_PROFILES`.

## Núcleo cognitivo — a IA comanda o scan (ADR-0007/0009)

O EIGAN é um **agente autônomo**: o subpacote `engine/cognitive/` transforma um
`Goal` (objetivo + perspectiva) num scan orquestrado pela IA.

```
Goal → Planner → [Agent → ToolSelector → SafeExecution] → Feedback → replan → Stop
```

- **`AgenticPlanner`** (padrão): a IA propõe o plano inicial (capacidades +
  ordem) e, a cada onda, a próxima — saída **estruturada validada (Pydantic v2)**,
  **grounded** no `PluginRegistry` (ids inventados descartados). Sob ele, o
  **`DeterministicPlanner`** (estratégia declarada + cascata) é o **substrato**
  que a IA comanda — não um "modo sem IA" (o scan exige um provedor; ADR-0012).
- **`ToolSelector`** (determinístico) escolhe a *ferramenta* de cada capacidade,
  com `reasons` auditáveis. A IA decide *capacidade*, nunca a ferramenta.
- **`SafeExecution`** valida o escopo por alvo antes de spawnar o runner seguro
  (lista de args, nunca `shell=True`). Alvo fora do escopo → *skipped*, registrado.
- **Cascata declarativa** (`CascadeGraph`) é o **piso de segurança**: roda sempre;
  a IA acrescenta e prioriza sobre ela.
- **Rastro auditável**: cada decisão vira `DecisionEntry` e um evento `log`
  transmitido à UI (timeline de raciocínio) — sem caixa-preta.

`StopCondition` impõe teto de orçamento/tempo (anti-loop); a IA pode encerrar
propondo nenhuma capacidade nova.

## AI-native: a IA é obrigatória (ADR-0012)

O EIGAN é um agente de IA — **sem um provedor configurado, o scan é recusado**
(erro acionável; `require_provider()`). A IA **comanda** o scan (planeja, seleciona
capacidades, reage e narra); os mecanismos determinísticos (cascata, `ToolSelector`,
`Enricher`/skills, Policy Engine, execução segura) são o **substrato que a IA
comanda e que a política arbitra** — nunca um caminho que a substitui. Para
privacidade/offline sem custo por token, o provedor pode ser **Ollama local**.

As **exportações** (JSON/SARIF/CSV) são serialização determinística dos findings
(reprodutíveis para SIEM); as **narrativas** (Técnico/Executivo) são geradas pela
IA e marcadas `ai_generated`.

## Red · Blue · Purple (caminhos de execução)

- **Red** — o `CognitiveEngine` comanda o scan (recon → **expansão de alvos**
  ADR-0018 → portas/serviços/web → `exposure` prober ADR-0023). Cada ação passa pelo
  **Policy Engine** (ADR-0011) e pelo cliente HTTP **blindado contra SSRF** (ADR-0015).
- **Blue** — caminho separado (`engine/blue.py`, ADR-0021): `log-analysis` detecta
  ataques em logs → `Finding` com técnica ATT&CK. `eigan blue` / `POST /api/v1/blue`.
- **Purple** — `analysis/purple.py` (ADR-0022) correlaciona Red×Blue → cobertura e
  pontos cegos. `eigan purple` / `POST /api/v1/purple`.
- **Remediação por IA** (ADR-0024) e narrativas são geradas pela IA (grounded,
  neutralizadas contra prompt-injection ADR-0016); as exportações são determinísticas.
- A **API/dashboard** exige token (ADR-0014); scans persistem **incrementalmente**
  (ADR-0017 — nada se perde se o scan morre).

## Roadmap

O roadmap vive numa fonte única, para não divergir:

- [docs/ROADMAP.md](ROADMAP.md) — o que está entregue × scaffold honesto por módulo.
- [docs/roadmap/autonomous-platform.md](roadmap/autonomous-platform.md) — a visão
  faseada da plataforma multiagente autônoma (real ✅ × roadmap ⬜).
