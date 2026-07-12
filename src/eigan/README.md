# `src/eigan/` — mapa do código

Pacote Python do EIGAN. Arquitetura em camadas (Clean/Hexagonal): **as dependências
apontam para dentro** — o domínio não conhece banco, rede nem ferramentas.

```
Interfaces  ─▶  Aplicação  ─▶  Domínio  ◀─  Infra
(cli, api)      (engine)       (findings,     (plugins, ai,
                               perspective)    report, store)
```

## Camadas e módulos

| Módulo | Camada | Responsabilidade |
|---|---|---|
| `capability.py`, `perspective.py` | **Domínio** | Conceitos de 1ª classe (Capability, Perspective) — sem I/O. |
| `findings/` | **Domínio** | Schema normalizado `Finding`, `store` (SQLite, Repository Pattern), dedup/correlação por `fingerprint`. |
| `engine/` | **Aplicação** | Orquestração determinística: `orchestrator`, `pipeline`, `registry`+`plugin` (auto-discovery), `cascade` (grafo declarativo), `risk`, `correlation`, `feeds`, `base` (runner seguro), `events`. |
| `engine/cognitive/` | **Aplicação** | Núcleo agêntico (a IA comanda o scan): `goal` → `planner` (Agentic/Deterministic) → `selection` → `agent` → `feedback` → `engine` (loop goal-driven). |
| `analysis/` | **Aplicação** | `inventory` (ativos), `attack` (MITRE ATT&CK), `compliance`, `diff` (memória entre scans). |
| `report/` | **Infra** | `deterministic` (HTML/PDF via Jinja) + `corporate` (capa/classificação/score/masking/gráficos) + `exporters` (JSON/CSV/SARIF) + `remediation` + `pdf_support` + `templates/`. |
| `ai/` | **Infra** | `provider` — camada multi-fornecedor (pré-requisito de execução, §3.4). |
| `policy/` | **Infra** | Policy/Guardrail Engine: `impact` (`ImpactClass`) + `engine` (`vet`). |
| `security/` | **Domínio/Segurança** | `scope` (guardrail), `consent` (gate), `onboarding`. Barreira legal — sem I/O de rede. |
| `knowledge/` | **Infra** | `loader` da base de skills (`SKILL.md`). |
| `api/` | **Interface** | FastAPI (`app`, `/api/v1` + WS), `scan_manager` (jobs em background) + `static/` (dashboard SPA). |
| `cli/` | **Interface** | Click: `main` (comandos), `menu`/`wizard`/`tui` (interativo), `session` (orquestra scan), `doctor`, `reporting`. |

## Onde adicionar coisas (expansão)

- **Nova ferramenta** → criar pasta em `plugins/<red\|blue\|purple>/<nome>/` (metadata + runner + parser + tests). **O Core não muda** (auto-discovery via `engine/registry.py`).
- **Novo provedor de IA** → registrar um `ProviderSpec` em `ai/provider.py`. Nada mais muda.
- **Novo formato de relatório** → um exporter em `report/exporters.py` ou template em `report/templates/`.
- **Nova capacidade cognitiva/agente** → `engine/cognitive/` (declara capacidades; o Planner as ativa).

Decisões arquiteturais (o *porquê*) estão em [`../../docs/adr/`](../../docs/adr/).
