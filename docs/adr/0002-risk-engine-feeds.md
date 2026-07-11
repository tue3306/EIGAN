# ADR-0002 — Risk Engine e feeds sem invenção

- **Status:** Aceito
- **Contexto:** priorização de risco exige EPSS/KEV/CVSS, mas o produto **não
  pode fabricar** score factual (regra inegociável §5 / anti-invenção).

## Decisão

O **Risk Engine** (`engine/risk.py`) combina sinais para um `RiskScore`:
CVSS (v3.1/v4), **EPSS** (probabilidade de exploração — FIRST.org), **CISA KEV**
(exploração conhecida), disponibilidade de exploit e criticidade do ativo.

Regra de ouro — **feeds vêm de fonte oficial, com cache; nunca de memória:**

- `engine/feeds.py` busca EPSS (FIRST.org) e KEV (CISA) e **cacheia** em
  `~/.cache/eigan/feeds/` (fora do repo). Comando dedicado:
  `eigan feeds update` (com verificação de integridade/hash e data do feed).
- Se um feed **não** foi obtido (offline, primeira execução), os campos EPSS/KEV
  saem **`UNVERIFIED`** e o `RiskScore` usa só o que é verificável (CVSS local).
  **Nunca** se inventa um número.
- O relatório e a API expõem a **procedência** (data do feed, fonte) de cada
  sinal. Item sem confirmação aparece marcado `UNVERIFIED`.

## Consequências

- **+** Offline-first e auditável; o produto roda sem rede (degrada, não mente).
- **+** Score reproduzível: dado o mesmo dataset + mesmos feeds cacheados, o
  resultado é determinístico.
- **−** Sem `feeds update`, a priorização é mais pobre (só CVSS). É o preço
  correto da veracidade.
