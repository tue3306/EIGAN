# Bloqueios conhecidos

Itens que não podem ser resolvidos de dentro do build autônomo. Cada bloqueio é
**isolado** (não impede o resto do trabalho).

| # | Bloqueio | Impacto | Contorno |
|---|---|---|---|
| 1 | **Push para o remoto exige PAT do GitHub.** Autenticação por senha está desativada no remoto. | O passo final (`git push`) não roda sem credencial. | Todo o trabalho é commitado localmente; o push é feito assim que o usuário fornecer um PAT (via `GIT_ASKPASS`, token só em variável de ambiente, nunca no repo/config). |
| 2 | **Binários das ferramentas externas** (nmap, nuclei, httpx…) podem não estar instalados no host. | Scans reais dependem das ferramentas. | O engine **pula** ferramenta ausente com aviso; `vulnforge doctor` lista o que falta e como instalar; Docker roda cada ferramenta em container efêmero. Testes usam fixtures de saída real, sem executar binários. |
| 3 | **Feeds EPSS/KEV** exigem rede na primeira atualização. | Sem `feeds update`, priorização usa só CVSS. | Offline-first: campos saem `UNVERIFIED`; `vulnforge feeds update` popula o cache quando houver rede (ver ADR-0002). |
