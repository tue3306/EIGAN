# ADR-0006 — Estratégia de provisão de ferramentas externas

- **Status:** aceito
- **Data:** 2026-07-10
- **Relaciona-se com:** CLAUDE.md §15 (Docker/sandbox), §3.2 (consent),
  §3.1/§5 (anti-invenção, segurança), [ADR-0005](0005-launcher-and-product-experience.md)
  (launcher)

## Contexto

O engine roda scanners externos por plugins. Hoje há **6 runners reais** (dnsx,
httpx, naabu, nmap, nuclei, subfinder); as demais ~27 entradas de
`config/tools.yaml` são *scaffold honesto* (§3.6). Cada runner real acha o
binário via `shutil.which()` — **espera a ferramenta já no PATH do host**. O
`CLAUDE.md §15` e o comentário em `engine/base.py` prometem "cada ferramenta em
container efêmero", mas isso **ainda não existe** (o compose sobe só a `api`).

A Missão 1 pede reduzir ao máximo o atrito de obter as ferramentas — sem violar
anti-invenção (não fixar versão/imagem/comando não verificado) nem menor
privilégio (não sair instalando como root silenciosamente).

Restrição factual que molda tudo: o `install_hint` das 5 ferramentas
ProjectDiscovery é a **URL oficial de instalação** (não um comando), justamente
para não fabricar comando/versão. Só o `nmap` traz um comando de pacote padrão.

## Opções consideradas

### (a) Executor em container (cumpre o §15)
Estender o `docker-compose.yml` com execução efêmera por ferramenta usando as
imagens oficiais `projectdiscovery/*` (5 ferramentas Go) + uma imagem fina para
`nmap` (apt/apk). Os runners passam a aceitar um **executor** (local via
`shutil.which` **ou** container) — o `engine/base.py` já antecipa a troca "mesmo
runner, executor diferente".
- **Prós:** zero dependência no host; sandbox de rede/escopo; é o que a doc
  promete; alinhado ao offline-first depois de baixar as imagens uma vez.
- **Contras:** refator real do `_run` (I/O por stdin/arquivo, captura de saída,
  privilégios de `nmap`/`naabu` para SYN scan, `--network`), imagens grandes, e
  **precisa de teste de integração contra as imagens** — não fabricar tags. Não
  dá para **verificar offline** aqui e agora (DoD exige pytest/verify verdes).

### (b) Publicação no PyPI (`vulnforge`, nome livre)
Trusted publishing no CI → `pipx install vulnforge` sem `git clone`.
- **Prós:** remove o atrito do **núcleo** (instala o pacote, não as ferramentas).
- **Contras:** **não instala as ferramentas externas**; exige que o **dono**
  registre o projeto no PyPI e configure o *trusted publisher* (OIDC) — não é
  executável de dentro do build autônomo.

### (c) `vulnforge doctor --install` (+ launcher `--with-tools`)
Subcomando que, **mediante confirmação explícita** (mesma filosofia do consent
gate, §3.2), provisiona **só as 6 ferramentas com runner real** que estão
ausentes, **listando exatamente o que vai rodar antes**.
- **Prós:** entregável e testável **agora**; offline-friendly; seguro (lista de
  argumentos, nunca `shell`; nunca fonte não oficial).
- **Contras:** limitado pelo que é **verificável**: para `nmap`, gera o comando
  do gerenciador de pacotes do SO; para as ferramentas ProjectDiscovery (hint =
  URL), **não fabrica** comando/versão — mostra a referência oficial + Docker e
  não executa por você.

## Decisão

As três **não são exclusivas**. Ordem escolhida, com dados do repo:

1. **(c) entra agora — implementado.** É o único caminho 100% entregável e
   verificável nesta iteração, e respeita anti-invenção e menor privilégio.
   Vive em `cli/doctor.py` (`plan_install` / `run_install`) e é acionável por
   `vulnforge doctor --install [--yes]` e por `python3 vulnforge.py --with-tools`.
2. **(a) é o alvo arquitetural (§15) — isolado em BLOCKERS.** Fica desenhado
   abaixo, mas depende de refatorar o executor + **revalidar tags** + testes de
   integração com Docker, que não dá para verificar offline. Ver
   `docs/BLOCKERS.md` #4.
3. **(b) fica pronto mas *owner-gated* — isolado em BLOCKERS.** O workflow
   `.github/workflows/publish.yml` já existe (trusted publishing, disparo em
   release), **inerte** até o dono registrar o projeto no PyPI e configurar o
   publisher OIDC. Ver `docs/BLOCKERS.md` #5.

### Plano concreto de (a), para a próxima missão

- Introduzir uma porta `ToolExecutor` no domínio do engine: `LocalExecutor`
  (comportamento atual, `shutil.which` + `subprocess`) e `DockerExecutor`
  (`docker run --rm [--network=…] <image> <args>`, alvo via stdin quando
  `target_via_stdin`). `BaseToolPlugin._run` passa a delegar ao executor
  injetado — **sem mudança de comportamento** no caminho local (SOLID/DI).
- Mapear cada ferramenta real → imagem oficial no `metadata.yaml`
  (`image:`/`image_ref:` com tag `# VERIFICAR` até confirmada na fonte).
- `docker/docker-compose.yml`: perfil `tools` com serviços efêmeros; `doctor`
  passa a reportar "disponível via Docker".
- Teste de integração **local** (DVWA/Juice Shop em container), nunca terceiros.

## Consequências

- ✅ Atrito de ferramentas cai já: `--with-tools`/`doctor --install` guiam e
  instalam o que é seguro/verificável, com consentimento explícito.
- ✅ Anti-invenção preservada: nada de comando/imagem/versão fabricados; o que
  não é verificável vira referência oficial + `# VERIFICAR`.
- ✅ Caminho para o §15 desenhado e rastreável (não hand-wave).
- ⚠️ Enquanto (a) não entra, ferramentas ProjectDiscovery ausentes seguem sendo
  **puladas** no scan (o engine já degrada) e apontadas pelo `doctor`.
- ⚠️ (b) depende de ação do dono no PyPI; documentado como bloqueio isolado.
