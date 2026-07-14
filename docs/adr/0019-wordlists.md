# ADR-0019 — Wordlists de verdade (SecLists) com fallback honesto

- **Status:** aceito
- **Data:** 2026-07-14
- **Relacionado:** CLAUDE.md §3.1 (não fingir cobertura), §13 (DX)

## Contexto

O ffuf usava uma wordlist **embutida de 80 linhas** → descoberta de conteúdo/
diretório/parâmetro fraquíssima. Pentest de verdade usa **SecLists** (milhares a
milhões de entradas), escolhendo o tamanho conforme o perfil.

## Decisão

Um resolvedor central de wordlists (`engine/wordlists.py`).

- **Detecta SecLists** (`/usr/share/seclists`, `/opt/SecLists`, `~/SecLists`, ou
  `EIGAN_WORDLIST_DIR`) e escolhe o arquivo por **objetivo** (content/params/dns) e
  **tamanho por perfil** (quick→small, standard→medium, deep→large).
- **2º melhor:** wordlists comuns do SO (dirb/dirbuster).
- **Fallback:** listas **curadas MÉDIAS embutidas** (`wordlists_data/*.txt`,
  300/176/190 entradas — muito maiores que 80), com **aviso de cobertura reduzida**
  (§3.1 — nunca fingir cobertura ampla).
- `WordlistChoice` carrega a **procedência** (seclists/system/builtin) para
  auditoria; o `doctor` mostra o SecLists detectado e qual wordlist por perfil.
- O ffuf resolve via `resolve("content", profile)`; o perfil chega via
  `tool_options` (novo campo `profile`).

## Consequências

- **Positivas:** com SecLists instalado, a descoberta de conteúdo fica de nível
  profissional; sem ele, a embutida é decente e o operador é avisado (honesto). O
  `EIGAN_WORDLIST_DIR` dá override explícito. Empacotado via `package-data`.
- **Fora de escopo (roadmap):** aplicar o resolvedor ao DNS brute-force (quando o
  plugin existir — ADR de profundidade de DNS) e ao exposure prober (cuja lista de
  caminhos sensíveis é curada, não um fuzzing genérico).
