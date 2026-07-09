# Roadmap comercial — apenas documentado

> **Status: não implementado (por decisão).** Este documento descreve
> funcionalidades comerciais que o VulnForge **poderá** ter no futuro. Nenhuma
> delas tem código nesta fase — o produto é e continua **open source (Apache-2.0)
> e funcional por completo sem qualquer camada paga**. Documentar aqui evita
> "vazamento" de escopo comercial para dentro do Core.

## Princípio

O núcleo do VulnForge (Core Engine, plugins do MVP, CLI, API, dashboard,
relatórios) **nunca** fica atrás de paywall. Qualquer oferta comercial seria uma
**camada por cima**, opcional, que não remove capacidade do open source.

## Itens planejados (sem código hoje)

| Área | Descrição | Estado |
|---|---|---|
| Portal de clientes | Área web multiusuário para gestão de engajamentos | Planejado |
| Login / SSO | Autenticação, OIDC/SAML, RBAC | Planejado |
| Multi-tenant | Isolamento por organização/cliente | Planejado |
| Pagamento / billing | Assinaturas, faturamento, medição de uso | Planejado |
| Planos | Tiers (Community/Pro/Enterprise) | Planejado |
| Licenciamento | Chaves de licença para a camada comercial | Planejado |
| API keys gerenciadas | Emissão/rotação de chaves para a API | Planejado |
| Marketplace de plugins | Distribuição de plugins de terceiros | Planejado |
| Cloud / SaaS | Execução gerenciada, filas distribuídas | Planejado |
| Self-hosted enterprise | Empacotamento suportado on-prem | Planejado |

## Fora de escopo agora

- Não há cobrança, telemetria comercial, nem chamada a serviço de licenciamento.
- Não há gate de funcionalidade por plano no código.
- Guardrails de segurança e legalidade (§3 do CLAUDE.md) **não** são "features
  premium" — são inegociáveis e sempre presentes.

Ver também: [../ROADMAP.md](../ROADMAP.md) (roadmap técnico/de produto).
