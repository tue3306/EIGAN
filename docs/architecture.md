# Arquitetura do VulnForge

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

## Modo com IA × sem IA

Cada função de enriquecimento passa pelo `Enricher`: se há provedor com chave,
usa IA (grounded na skill relevante, saída marcada `ai_generated`); senão, cai
para `DeterministicEnricher`, que monta explicação/remediação a partir da skill
casada por CWE/OWASP. O relatório e o dashboard nunca dependem de IA.

## Roadmap por fases

- **Fase 0–2 (implementado):** guardrail, schema, store, engine (nmap/nuclei),
  dedup, base de conhecimento, relatório determinístico HTML/PDF.
- **Fase 3:** dashboard React, WebSocket de progresso real, auth + RBAC.
- **Fase 4:** provedores de IA concretos (Anthropic/OpenAI/Google/Ollama),
  redaction de PII/segredos, cache de tokens.
- **Fase 5:** mais adapters (ZAP/nikto/trivy/testssl), `.deb` + systemd,
  atualização de feeds com verificação de integridade, testes de integração
  contra DVWA/Juice Shop local.
```
