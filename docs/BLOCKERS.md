# Bloqueios conhecidos

Itens que não podem ser resolvidos de dentro do build autônomo. Cada bloqueio é
**isolado** (não impede o resto do trabalho).

| # | Bloqueio | Impacto | Contorno |
|---|---|---|---|
| 1 | **Push para o remoto exige PAT do GitHub.** Autenticação por senha está desativada no remoto. | O passo final (`git push`) não roda sem credencial. | Todo o trabalho é commitado localmente; o push é feito assim que o usuário fornecer um PAT (via `GIT_ASKPASS`, token só em variável de ambiente, nunca no repo/config). |
| 2 | **Binários das ferramentas externas** (nmap, nuclei, httpx…) podem não estar instalados no host. | Scans reais dependem das ferramentas. | O engine **pula** ferramenta ausente com aviso; `eigan doctor` lista o que falta e como instalar; Docker roda cada ferramenta em container efêmero. Testes usam fixtures de saída real, sem executar binários. |
| 3 | **Feeds EPSS/KEV** exigem rede na primeira atualização. | Sem `feeds update`, priorização usa só CVSS. | Offline-first: campos saem `UNVERIFIED`; `eigan feeds update` popula o cache quando houver rede (ver ADR-0002). |
| 4 | **Executor em container (§15)** — rodar cada ferramenta em container efêmero exige refatorar o executor dos runners + **revalidar as tags** das imagens oficiais + testes de integração com Docker. Não verificável offline nesta iteração; não fabrico tag/imagem (§3.1). | Ferramentas ProjectDiscovery ausentes no host seguem sendo **puladas** no scan. | ADR-0006: entra na próxima missão com a porta `ToolExecutor` (Local/Docker), sem mudar o caminho local. Enquanto isso, `doctor --install` / `python3 eigan.py --with-tools` provisiona o que é seguro e o engine pula o que falta (com aviso no `doctor`). |
| 5 | **Publicação no PyPI (`eigan`)** exige que o **dono** registre o projeto no PyPI e configure o *trusted publisher* (OIDC). Não executável no build autônomo. | Sem `pipx install eigan`; instalação do núcleo segue por `git clone` + `python3 eigan.py`. | `.github/workflows/publish.yml` já pronto (trusted publishing, dispara em GitHub Release). Ativa sozinho assim que o dono configurar o publisher — sem tocar em segredo no repo. |
| 6 | **Renome do repositório no GitHub para `eigan`** (ADR-0009). O ambiente **não tem `gh` autenticado**, então `gh repo rename eigan` não roda daqui; renomear o repo é ação de **Settings → Rename** do dono. | O remoto segue `github.com/tue3306/vulnerability-scanner`; badges/links do README apontam para o nome atual (o GitHub redireciona automaticamente após o rename). | O código já está renomeado para EIGAN (pacote/comando/produto). Após o dono renomear no GitHub, rode `git remote set-url origin https://github.com/tue3306/eigan.git`. Enquanto isso, o remoto atual funciona normalmente (o GitHub mantém o redirect). |
| 7 | **"About" do repositório (descrição + tópicos + site)** — o GitHub só aceita via API/`gh` autenticado; o ambiente **não tem `gh` nem token**. | O repo aparece "No description, website, or topics provided". | O dono roda **um** dos comandos abaixo (token com escopo `repo`). Descrição e tópicos sugeridos prontos: |

### Definir o "About" do repositório (rode você mesmo)

Com **gh** (`gh auth login` antes):

```bash
gh repo edit tue3306/vulnerability-scanner \
  --description "EIGAN — scanner de vulnerabilidades dirigido por IA (Red/Blue/Purple): a IA planeja, executa e narra o pentest, com dashboard em tempo real e relatórios Técnico/Executivo." \
  --add-topic security --add-topic cybersecurity --add-topic pentesting \
  --add-topic vulnerability-scanner --add-topic ai-agent --add-topic red-team \
  --add-topic blue-team --add-topic osint --add-topic devsecops \
  --add-topic python --add-topic fastapi --add-topic nuclei --add-topic nmap
```

Sem gh, via **API** (defina `GITHUB_TOKEN` com escopo `repo`; o token nunca vai para o repo):

```bash
curl -sf -X PATCH -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/tue3306/vulnerability-scanner \
  -d '{"description":"EIGAN — scanner de vulnerabilidades dirigido por IA (Red/Blue/Purple): a IA planeja, executa e narra o pentest, com dashboard em tempo real e relatórios Técnico/Executivo."}'

curl -sf -X PUT -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/tue3306/vulnerability-scanner/topics \
  -d '{"names":["security","cybersecurity","pentesting","vulnerability-scanner","ai-agent","red-team","blue-team","osint","devsecops","python","fastapi","nuclei","nmap"]}'
```
