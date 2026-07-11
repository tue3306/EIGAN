# Contribuindo com o EIGAN

Obrigado por querer contribuir! O EIGAN é uma plataforma modular de operações
de segurança (Red/Blue/Purple). Este guia mostra como preparar o ambiente,
manter o padrão de qualidade e — o mais importante — **adicionar um plugin em
~5 minutos** sem tocar no Core.

> ⚠️ Antes de qualquer coisa, leia o [Código de Conduta](CODE_OF_CONDUCT.md) e o
> [aviso legal de uso autorizado](README.md#-aviso-legal). Contribuições que
> incentivem uso não autorizado serão recusadas.

## Ambiente de desenvolvimento

Requer **Python 3.11+**.

```bash
git clone https://github.com/tue3306/vulnerability-scanner.git
cd vulnerability-scanner
python -m venv .venv && source .venv/bin/activate
pip install -e ".[pdf,ai,dev]"
eigan doctor          # confere ambiente, ferramentas, IA e feeds
```

## Definition of Done (obrigatório antes do PR)

Um PR só está pronto quando **tudo** abaixo passa localmente:

```bash
ruff format .                       # format
ruff check src plugins tests        # lint
mypy src                            # type-check
pytest -q                           # testes (unit + integração local)
```

Sem código morto, sem `TODO` órfão, sem segredo commitado. Documentação do
módulo/plugin atualizada. Commits pequenos e descritivos (padrão
[Conventional Commits](https://www.conventionalcommits.org/), ex.:
`feat(red): plugin ffuf para content discovery`).

## Adicionar um plugin em ~5 minutos

O Core faz **auto-discovery** por `metadata.yaml` (ADR-0001/0003): você **não
edita o Core** para somar uma ferramenta — cria uma pasta.

1. Copie o esqueleto de um plugin existente da mesma categoria:
   ```bash
   cp -r plugins/red/naabu plugins/red/masscan
   ```
2. Edite `metadata.yaml` (nome, `capabilities`, `supported_perspectives`,
   `tool`, `version_source` com `# VERIFICAR`, `license`, `commercial_use`,
   `install_hint`).
3. Implemente `runner.py` (subprocess seguro — **lista de argumentos, nunca
   `shell=True`**) e `parser.py` (normaliza a saída para o schema de `Finding`).
4. Adicione `tests/test_parser.py` com **fixture de saída real** da ferramenta.
5. Rode `eigan doctor` — o plugin aparece descoberto; `pytest -q` deve passar.

Detalhes e contrato completo: `plugins/README.md` e `docs/architecture.md`.

### Módulo ainda não implementado? Scaffold honesto, nunca stub falso

Módulos fora do MVP entram como **scaffold honesto**: `metadata.yaml` com
`roadmap: true` + `docs/` + teste marcado `roadmap`. Eles são descobertos e
listados, mas **não fingem executar**. Nunca faça um stub que simula resultado.

## Regras inegociáveis (não afrouxáveis em PR)

Herdadas do [CLAUDE.md](CLAUDE.md) §3:

1. **Anti-invenção:** CVE/CVSS/EPSS/KEV/versão/licença não verificados saem
   `UNVERIFIED` — nunca fabricados.
2. **Autorização sempre presente:** guardrail de escopo e consent gate não são
   removidos, no máximo simplificados.
3. **A IA nunca executa scanner nem descobre vulnerabilidade** — só interpreta.
4. **Todo recurso de IA tem fallback determinístico** (funciona sem chave).
5. **Segurança de código:** sem `shell=True`, sem concatenar comando, sem
   secret no repo, validação/sanitização sempre.

## Fluxo de PR

1. Faça fork e crie um branch a partir de `main` (`feat/...`, `fix/...`).
2. Garanta a DoD verde e atualize o `CHANGELOG.md` (seção *Unreleased*).
3. Abra o PR preenchendo o template; descreva o *porquê*, não só o *o quê*.
4. Um mantenedor revisa; discussões técnicas são bem-vindas.

## Reportar bugs e vulnerabilidades

- Bug funcional → abra uma Issue pelo template.
- **Vulnerabilidade de segurança no próprio EIGAN** → **não** abra Issue
  pública; siga o [SECURITY.md](SECURITY.md).

Dúvidas de arquitetura? Veja `docs/architecture.md` e os ADRs em `docs/adr/`.
