# ADR-0023 — Exposure prober (arquivos/segredos vazados)

- **Status:** aceito (retroativo — decisão já implementada)
- **Data:** 2026-07-14
- **Relacionado:** CLAUDE.md §3.1 (grounding), ADR-0015 (SSRF), CWE-200/CWE-540,
  MITRE ATT&CK T1552/T1592

## Contexto

Um pilar de "dados vazados" que um atacante encontra de fora: `.git/`, `.env`,
backups, `.aws/`, chaves privadas, `server-status`, `phpinfo`, e segredos embutidos
nas respostas (chaves AWS/Google/Slack/GitHub).

## Decisão

Plugin Red `exposure` (nativo Python, capability `secrets_exposure`, impacto
`active_safe` — só GETs de identificação de recursos públicos). Para cada caminho
sensível confirma a exposição por **assinatura de conteúdo** (não só o status) e
varre as respostas por segredos com **regex + validação**, **mascarando** o segredo
na evidência. Mapeado a CWE + ATT&CK. **Grounded**: só reporta o que o alvo
realmente serve (§3.1). Todo acesso HTTP passa pelo cliente **blindado contra SSRF**
(ADR-0015): não segue redirect cego, bloqueia metadata, fixa o IP validado.

## Consequências

- **Positivas:** superfície de "dados vazados" real, mascarada e grounded, na
  cascata/pipeline/goals do Red.
- **Fora de escopo (roadmap):** ampliar a lista de caminhos sensíveis com SecLists
  quando disponível ([[0019-wordlists]]); mais assinaturas de segredo.
