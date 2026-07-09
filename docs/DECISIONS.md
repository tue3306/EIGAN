# Registro de Decisões (ADR log)

Decisões arquiteturais são registradas como ADRs curtos em `docs/adr/`. Este
índice existe para leitura rápida; a fonte de verdade é cada arquivo.

| ADR | Título | Status |
|---|---|---|
| [0001](adr/0001-plugin-capability-architecture.md) | Arquitetura de Plugins orientada a Capabilities | Aceito |
| [0002](adr/0002-risk-engine-feeds.md) | Risk Engine e feeds sem invenção | Aceito |
| [0003](adr/0003-plugins-directory-layout.md) | Localização e carregamento dos plugins | Aceito |

## Princípios que nenhum ADR pode afrouxar (inegociáveis)

1. Não inventar dado factual — CVE/EPSS/KEV/CVSS/versão/licença não verificados
   saem `UNVERIFIED`.
2. Afirmação de autorização sempre presente; travas público×privado por
   perspectiva mantidas.
3. IA nunca executa scanner nem descobre vulnerabilidade.
4. Toda função de IA tem fallback determinístico; o produto roda sem chave.
5. Segurança de código sempre (sem `shell=True`, sem concatenar comando, sem
   secret no repo, validação/sanitização).
6. Módulo não construído fica **scaffolded honesto**, nunca stub que finge
   funcionar.
