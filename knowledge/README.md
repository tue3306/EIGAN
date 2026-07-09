# knowledge/ — Base de conhecimento (determinística)

O que permite ao VulnForge **explicar, remediar e mapear** findings **sem
nenhuma IA**. É a fonte do fallback determinístico e também o *grounding* quando
há IA (a IA recebe só isto + findings, e é proibida de afirmar fora daqui).

## Conteúdo

- **`skills/<nome>/SKILL.md`** — base no padrão *agentskills* (uma skill por
  vulnerabilidade/tema). Hoje: `sql-injection`, `xss`, `weak-tls`. Cada skill
  traz explicação por público, impacto, remediação e referências verificáveis.
  Casada por CWE/OWASP com o finding.
- **`attack/techniques.yaml`** — mapa de findings → técnicas MITRE ATT&CK
  (usado pela análise Purple e pelo gap analysis).
- **`compliance/mappings.yaml`** — mapeamentos indicativos (ex.: CWE → OWASP /
  NIST) para a análise Blue de conformidade.

## Como adicionar uma skill

Crie `knowledge/skills/<slug>/SKILL.md` seguindo o formato das existentes
(frontmatter + seções por público + remediação + `references`). Referências
devem ser **URLs verificáveis** de fonte oficial; nada de fato não confirmado
(CLAUDE.md §5). A skill passa a alimentar relatório e IA automaticamente.
