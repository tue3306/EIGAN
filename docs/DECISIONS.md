# Registro de Decisões (ADR log)

Decisões arquiteturais são registradas como ADRs curtos em `docs/adr/`. Este
índice existe para leitura rápida; a fonte de verdade é cada arquivo.

| ADR | Título | Status |
|---|---|---|
| [0001](adr/0001-plugin-capability-architecture.md) | Arquitetura de Plugins orientada a Capabilities | Aceito |
| [0002](adr/0002-risk-engine-feeds.md) | Risk Engine e feeds sem invenção | Aceito |
| [0003](adr/0003-plugins-directory-layout.md) | Localização e carregamento dos plugins | Aceito |
| [0004](adr/0004-cascade-orchestration-and-web-ui.md) | Orquestração em cascata + interface web | Aceito |
| [0005](adr/0005-launcher-and-product-experience.md) | Launcher e experiência de produto ("baixa e roda") | Aceito |
| [0006](adr/0006-tool-provisioning-strategy.md) | Estratégia de provisionamento de ferramentas | Aceito |
| [0007](adr/0007-cognitive-core-planner.md) | Núcleo cognitivo (Planner → Selection → Execution → Feedback) | Aceito |
| [0008](adr/0008-agent-platform-ten-pillars.md) | Plataforma de agente — 10 pilares | Aceito |
| [0009](adr/0009-eigan-autonomous-agent.md) | EIGAN: agente autônomo dirigido por IA + renome | Aceito |
| [0010](adr/0010-ai-provider-registry.md) | Registro modular de provedores de IA | Aceito |
| [0011](adr/0011-policy-guardrail-engine.md) | Policy / Guardrail Engine | Aceito |
| [0012](adr/0012-ai-native-mandatory.md) | IA obrigatória (AI-native, sem "modo sem IA") — supera a postura AI-opcional | Aceito |

## Princípios que nenhum ADR pode afrouxar (inegociáveis)

1. Não inventar dado factual — CVE/EPSS/KEV/CVSS/versão/licença não verificados
   saem `UNVERIFIED`.
2. Afirmação de autorização sempre presente; travas público×privado por
   perspectiva mantidas.
3. A IA planeja, decide e **comanda** o scan; a execução real passa por plumbing
   seguro + gate de escopo, e a IA nunca opera fora do escopo autorizado nem
   afirma fato fora das evidências (ADR-0009).
4. **IA obrigatória — sem IA, sem scan** (AI-native, ADR-0012): sem um provedor
   configurado, o scan é recusado. Os mecanismos determinísticos são o substrato
   que a IA comanda, não um "modo sem IA".
5. Segurança de código sempre (sem `shell=True`, sem concatenar comando, sem
   secret no repo, validação/sanitização).
6. Módulo não construído fica **scaffolded honesto**, nunca stub que finge
   funcionar.
