# ADR-0013 — Gestão de credenciais de FERRAMENTA (chaves declarativas + licenciamento)

- **Status:** aceito
- **Data:** 2026-07-14
- **Relacionado:** ADR-0010 (registro de provedor de IA), ADR-0012 (AI-native),
  CLAUDE.md §3.1 (anti-invenção), §3.6 (scaffold honesto), §5 (pesquisa/veracidade),
  §13 (DX "baixa e roda")

## Contexto

O EIGAN gerencia com cuidado a chave da **IA** (`ai/provider.py` + menu), mas não
tinha nenhuma gestão de credencial de **ferramenta**. O campo `requires_credentials`
em `PluginMetadata` era *metadata morta* — ninguém o lia. Consequências reais e
silenciosas:

- `wpscan` sem `WPSCAN_API_TOKEN` enumera, mas **não consulta as CVEs** conhecidas
  de plugins/temas de WordPress.
- `subfinder` sem as fontes OSINT (Shodan/Censys/VirusTotal/SecurityTrails) acha
  apenas uma **fração** dos subdomínios.
- Ferramentas **pagas/GUI** (ex.: Burp Suite Pro) não tinham como ser declaradas —
  ou seriam um stub que finge rodar (proibido, §3.6).

O operador não sabia que o resultado era parcial. Isso viola a veracidade (§3.1:
não fingir cobertura que não houve) e a DX (§13).

## Decisão

Uma camada **declarativa** de credenciais de ferramenta, análoga à da IA:

- **`engine/credentials.py`**: `ToolCredential` (env var, `required`, `obtain_url`,
  `degrades`, `provider`), o enum **`Licensing`** (`free | api_key | paid`),
  `CredentialState` (resolução contra o ambiente) e `coverage_warning()` (o aviso
  honesto do que NÃO foi coletado).
- **`metadata.yaml`** ganha `credentials:` e `licensing:`. `requires_credentials`
  passa a ser **derivado** (uma credencial obrigatória o implica), preservando
  override explícito. `licensing: paid` marca ferramentas comerciais/GUI que o
  agente **não automatiza** — declaradas honestamente, nunca fingindo executar
  (§3.6). O `burp` entra como scaffold `roadmap: true` + `paid`.
- **`doctor`** mostra, por ferramenta: chave configurada / ausente → **PARCIAL**
  (com a URL para obter) / obrigatória FALTANDO / 💳 paga-não-automatizada.
- **Menu → Configuração → "chaves de ferramenta"** grava no `.env` (chmod 600,
  **nunca ecoando** a chave) e, para o `subfinder`, gera/atualiza o
  `~/.config/subfinder/provider-config.yaml` (preservando provedores não geridos).
- **Runtime:** o `CognitiveEngine` emite na timeline `[cobertura] <tool>: PARCIAL …`
  quando uma chave **opcional** falta — auditável, sem inventar (§3.1). A entrega
  da env var às ferramentas continua sendo o *inheritance* de ambiente do
  subprocess (`engine/base.py`), já existente.

## Consequências

- **Positivas:** cobertura deixa de degradar em silêncio; o operador vê e resolve;
  ferramentas pagas são honestas (declaradas, não fingidas); adicionar credencial a
  um plugin é só editar o `metadata.yaml` (Core intacto).
- **Neutras/custos:** credenciais obrigatórias ausentes NÃO são "cobertura parcial"
  (a ferramenta nem rende útil) — são sinalizadas à parte no `doctor`. Chaves vivem
  só em env/arquivo, nunca commitadas nem impressas (§5).
- **Fora de escopo (roadmap):** plugins passivos key-gated (Shodan/Censys como
  fonte própria de enriquecimento); runner real do Burp Enterprise via REST API.
