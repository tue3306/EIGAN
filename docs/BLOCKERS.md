# Bloqueios conhecidos

Itens que não podem ser resolvidos de dentro do build autônomo. Cada bloqueio é
**isolado** (não impede o resto do trabalho).

| # | Bloqueio | Impacto | Contorno |
|---|---|---|---|
| 1 | **Push para o remoto exige PAT do GitHub.** Autenticação por senha está desativada no remoto. | O passo final (`git push`) não roda sem credencial. | Todo o trabalho é commitado localmente; o push é feito assim que o usuário fornecer um PAT (via `GIT_ASKPASS`, token só em variável de ambiente, nunca no repo/config). |
| 2 | **Binários das ferramentas externas** (nmap, nuclei, httpx…) podem não estar instalados no host. | Scans reais dependem das ferramentas. | O engine **pula** ferramenta ausente com aviso; `vulnforge doctor` lista o que falta e como instalar; Docker roda cada ferramenta em container efêmero. Testes usam fixtures de saída real, sem executar binários. |
| 3 | **Feeds EPSS/KEV** exigem rede na primeira atualização. | Sem `feeds update`, priorização usa só CVSS. | Offline-first: campos saem `UNVERIFIED`; `vulnforge feeds update` popula o cache quando houver rede (ver ADR-0002). |
| 4 | **Executor em container (§15)** — rodar cada ferramenta em container efêmero exige refatorar o executor dos runners + **revalidar as tags** das imagens oficiais + testes de integração com Docker. Não verificável offline nesta iteração; não fabrico tag/imagem (§3.1). | Ferramentas ProjectDiscovery ausentes no host seguem sendo **puladas** no scan. | ADR-0006: entra na próxima missão com a porta `ToolExecutor` (Local/Docker), sem mudar o caminho local. Enquanto isso, `doctor --install` / `python3 vulnforge.py --with-tools` provisiona o que é seguro e o engine pula o que falta (com aviso no `doctor`). |
| 5 | **Publicação no PyPI (`vulnforge`)** exige que o **dono** registre o projeto no PyPI e configure o *trusted publisher* (OIDC). Não executável no build autônomo. | Sem `pipx install vulnforge`; instalação do núcleo segue por `git clone` + `python3 vulnforge.py`. | `.github/workflows/publish.yml` já pronto (trusted publishing, dispara em GitHub Release). Ativa sozinho assim que o dono configurar o publisher — sem tocar em segredo no repo. |
