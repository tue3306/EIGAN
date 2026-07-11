# ADR-0003 — Localização e carregamento dos plugins

- **Status:** Aceito
- **Contexto:** onde os plugins vivem afeta discovery, imports e empacotamento.

## Decisão

Plugins de primeira parte vivem em **`plugins/` na raiz do repositório**,
organizados por categoria (`plugins/red/`, `plugins/blue/`, `plugins/purple/`),
conforme a visão do produto. Cada plugin é uma pasta autocontida (ver ADR-0001).

**Carregamento:** o `PluginRegistry` (`engine/registry.py`):

1. resolve as raízes de plugins nesta ordem: `$EIGAN_PLUGINS_DIR` (se
   definido) → `<raiz-do-repo>/plugins` → `<pacote>/plugins` (fallback
   empacotado). Raízes inexistentes são ignoradas;
2. adiciona o **pai** da raiz ao `sys.path` e importa cada plugin como pacote
   regular (`plugins.<categoria>.<nome>.runner`), o que faz **imports relativos**
   (`from .parser import parse`) funcionarem;
3. varre `**/metadata.yaml`, valida os metadados e instancia o runner;
4. **isola falhas:** um plugin com metadados inválidos ou import quebrado é
   registrado como *degradado* e **não** derruba o registry.

## Alternativas consideradas

- **Plugins dentro do pacote** (`src/eigan/plugins/`): imports triviais, mas
  menos visível como "catálogo de módulos" e menos convidativo a contribuições.
  Mantido como *fallback empacotado* para instalação via wheel.
- **Entry points (`importlib.metadata`)**: ótimo para plugins de terceiros
  distribuídos como pacotes; fica no roadmap. Auto-discovery por pasta atende o
  requisito atual (adicionar pasta = adicionar plugin) sem exigir reinstalação.

## Consequências

- **+** `plugins/` no topo é o "mapa de capacidades" do produto, editável sem
  tocar o Core.
- **−** Depende de `sys.path` para a raiz externa; encapsulado no registry e
  coberto por teste de discovery.
