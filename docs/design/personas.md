# Personas da interface

Público-alvo da interface web do VulnForge (§1 do prompt de interface). A UI é
calibrada para que **cada persona chegue ao que precisa sem tocar a CLI**.

| Persona | O que quer | Onde a UI atende |
|---|---|---|
| **Admin de TI** | Resumo, "estou seguro?", não detalhe técnico | Painel: KPIs, ativos em risco, "Novo Scan" em 1 clique |
| **CISO / Diretoria** | Risco executivo, tendência, ativos críticos | Painel + relatório Executivo (HTML/PDF), KPIs de severidade/KEV |
| **Pentester / Analista** | Detalhe, expandir descobertas, ver cascata | Progresso em tempo real, cascade-log justificado, detalhe do scan, relatório Técnico |
| **Developer / DevSecOps** | API, integração, CI, logs | REST `/api/v1`, WebSocket, SARIF, CLI headless (`--fail-on`) |

## Princípios de design derivados

1. **Zero linha de comando para o usuário final.** A CLI existe para dev/CI e
   power users; a jornada padrão é clicar "Novo Scan" → wizard → progresso →
   relatório.
2. **Progressive disclosure.** O wizard esconde complexidade (opções avançadas
   colapsadas); o painel mostra o essencial e permite descer ao detalhe.
3. **Sem mágica.** Toda ferramenta disparada em cascata aparece com a
   justificativa ("porta 445 → enum4linux"). O analista pode auditar cada passo.
4. **Honestidade.** Sinais não confirmados saem como `UNVERIFIED`; ferramentas
   roadmap aparecem como *sugeridas, não executadas*.

## Referências de UX (benchmarking)

Padrões observados em Burp Suite, OWASP ZAP e OpenVAS/Greenbone que informaram a
tela de progresso e a árvore de descobertas: botão de novo scan sempre visível,
progresso por fase, descobertas chegando em tempo real, filtro por severidade.
A cascata justificada é o diferencial: as ferramentas citadas mostram *o que*
rodou, não *por que* — aqui cada disparo é explicado.
