# ADR-0005 — Launcher único + experiência de produto (Missão 0)

- **Status:** aceito
- **Data:** 2026-07-10
- **Relaciona-se com:** [ADR-0004](0004-cascade-orchestration-and-web-ui.md)
  (interface web), CLAUDE.md §13 (DX/UX "baixa e roda") e §18 (interface como
  porta de entrada)

## Contexto

O repositório estava organizado como uma **biblioteca Python** (layout `src/`,
entrada só via `pip install` + comando `eigan`, ou `python -m eigan`).
Ao clonar, não havia ponto de entrada óbvio: a pergunta "como eu uso isso?" não
tinha resposta imediata. Todos os casos de uso já existiam (wizard, `serve`,
`doctor`, `feeds`, store, relatórios) — faltava a **camada de produto** que os
apresentasse sem exigir conhecimento da estrutura interna.

Meta (Missão 0): `git clone` → um comando → menu → primeiro scan → dashboard →
relatório em **menos de 3 minutos**, sem tocar na estrutura do projeto.

Restrições do CLAUDE.md que moldaram a decisão:

- §13 "baixa e roda": instalação e primeiro uso extremamente simples; autoconfig
  na 1ª execução; erros acionáveis, nunca stack trace cru; nada essencial exige
  editar YAML.
- §3.4 / §7: todo recurso tem **fallback determinístico**; nada essencial
  depende de dependência opcional.
- §5.5: subprocess seguro (lista de argumentos, nunca `shell=True`).
- §2: consent gate/autorização preservados — a camada de produto não afrouxa
  nenhuma trava de segurança.

## Decisão

### 1. Launcher único `eigan.py` na raiz (só stdlib)

Ponto de entrada que um usuário precisa conhecer:

```
git clone …  &&  cd ScanVuln  &&  python3 eigan.py
```

Num clone limpo ele **cria `.venv`, instala o pacote** (tentando o extra
`[tui]`, com fallback para a base), **gera `.env`** a partir de `.env.example` e
**reexecuta a si mesmo dentro do venv**, abrindo o menu. Se o pacote já é
importável (venv ativo, `pip install -e .`, Docker), pula o bootstrap. Argumentos
são repassados à CLI (`python3 eigan.py scan alvo.com`). Um atalho de shell
`./eigan` chama o mesmo script.

Detalhes que valem registro:

- **Colisão de nome resolvida.** Um arquivo `eigan.py` na raiz *sombreia* o
  pacote `eigan`. O launcher remove o diretório do script de `sys.path`
  (`_deshadow`) antes de qualquer import e detecta o pacote pelo **submódulo**
  `eigan.cli.main` (o script não é um pacote). A sondagem do venv usa
  `python -I` (isolado de cwd/PYTHON*), evitando o mesmo sombreamento.
- **Sem loop de bootstrap.** Uma flag de ambiente (`EIGAN_BOOTSTRAPPED`)
  marca a reexecução; se ainda assim não importar, o launcher falha com
  instruções manuais em vez de repetir.
- **Só stdlib.** O launcher não pode depender de nada instalável — ele é quem
  instala. Usa `venv`, `subprocess` (lista de args), `shutil`, `pathlib`.

### 2. Menu de produto (`cli/menu.py`)

`eigan` sem argumentos passa a abrir um **menu numerado** (Novo Scan,
Dashboard, Histórico, Configuração, Doctor, Atualizar Ferramentas, Sair). É uma
camada fina: **nenhuma regra de negócio nova** — cada opção orquestra um caso de
uso existente. As ações recebem `input_fn`/`echo` injetáveis (como
`cli/session.py`), o que as torna testáveis sem TTY. O menu é resiliente: erro
de uma ação vira mensagem acionável, nunca stack trace (§13).

### 3. TUI full-screen com Textual, opcional e com fallback (`cli/tui.py`)

Quando há TTY **e** a Textual está instalada (extra `[tui]`), a porta de entrada
é uma **TUI full-screen** que reusa o banner e as mesmas ações do menu. Todo
`import textual` acontece dentro de `run_tui` — importar o módulo nunca falha.
Sem Textual (ou em terminal problemático), cai no **menu numerado**
determinístico. Cada seleção sai da tela cheia, roda a ação no console (reusando
os fluxos `click` existentes) e reabre a TUI: superfície mínima, baixo risco.

### 4. Dashboard abre o navegador (`serve --open`)

`serve` ganhou `--open/--no-open` (padrão: abre em terminal interativo). Uma
thread daemon espera a porta responder (poll de socket) e então chama
`webbrowser.open`; headless, apenas imprime a URL. A opção **Dashboard** do menu
usa o mesmo caminho.

## Divergência declarada do CLAUDE.md

§13/§18 descrevem `eigan` sem argumentos abrindo **o wizard**. Passamos a
abrir **o menu**, com o wizard como opção 1 (Novo Scan). Seguimos a instrução do
chat (Missão 0), que pede o menu como cara do produto — o wizard continua
inteiro e alcançável. Divergência de baixo impacto: superset do comportamento
anterior, sem remover fluxo.

## Alternativas consideradas

- **Só a TUI Textual (sem menu stdlib).** Rejeitado: violaria o fallback
  determinístico (§3.4/§7) e quebraria em terminais sem suporte/headless. Textual
  é o *luxo*; o menu numerado é o *piso garantido*.
- **Launcher dependendo de Rich/Click.** Impossível: num clone limpo nada está
  instalado; o launcher tem de ser stdlib puro.
- **Renomear o pacote ou o script para evitar a colisão de nome.** Rejeitado: o
  usuário pediu explicitamente `python3 eigan.py`; a colisão é contornável
  com `_deshadow` + checagem por submódulo.
- **Instalar no sistema em vez de venv.** Rejeitado: PEP 668 bloqueia ambientes
  gerenciados e poluir o sistema é hostil. O venv em `.venv` é isolado e
  descartável.

## Consequências

- ✅ `git clone && python3 eigan.py` funciona sem pré-requisitos além de
  Python 3.11+ (e `python3-venv`, com dica acionável se faltar).
- ✅ Core intacto: o menu/TUI/launcher são camadas externas que só chamam a CLI.
- ✅ Segurança preservada: consent gate, termo de 1ª execução e guardrails de
  perspectiva seguem no caminho do scan (o menu delega ao wizard/`session`).
- ✅ Testável: helpers do launcher e roteamento do menu cobertos por unit tests;
  bootstrap real (venv + `pip install -e .[tui]`) e a TUI Textual validados
  manualmente ponta a ponta.
- ⚠️ Ter um `eigan.py` na raiz com o mesmo nome do pacote exige o cuidado de
  `sys.path` acima; rodar `import eigan` a partir da raiz do repo (sem o
  launcher) pega o script. Não é um fluxo suportado — usa-se `python3
  eigan.py` ou o comando instalado.
- ⚠️ Textual é dependência opcional: a experiência premium só aparece com
  `[tui]` instalado (o launcher instala por padrão; `pip install -e .` sozinho
  entrega o menu numerado).
