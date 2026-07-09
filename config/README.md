# config/ — Configuração declarativa

Configuração que dirige comportamento **por dados**, não por código espalhado.
Nada aqui precisa ser editado para o primeiro uso (zero-config; o wizard e os
padrões cuidam disso) — estes arquivos são para ajuste fino.

## Arquivos

- **`profiles.yaml`** — perfis de scan (`quick`, `standard`, `deep`,
  `network-only`, `web-only`): quais estágios/capabilities rodam em cada um.
- **`tools.yaml`** — inventário de ferramentas externas e suas versões. Versões
  ficam marcadas `# VERIFICAR` e são resolvidas contra a fonte oficial — **nunca
  fixadas de memória** (CLAUDE.md §5, anti-invenção).
- **`ai.yaml`** — provedores de IA (Anthropic/OpenAI/Google/Ollama), modelo
  padrão e chaves **por variável de ambiente** (nunca no arquivo). Sem chave, o
  fallback determinístico assume — o produto funciona igual.

## Precedência

Padrões do código → `config/*.yaml` → flags de CLI → variáveis de ambiente
(mais específicas vencem). Segredos **só** por env (`.env` a partir de
`.env.example`), nunca commitados.
