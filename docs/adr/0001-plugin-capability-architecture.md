# ADR-0001 — Arquitetura de Plugins orientada a Capabilities

- **Status:** Aceito
- **Contexto:** o Core precisa crescer para 100+ módulos sem ser reescrito.

## Decisão

Adotar **Capabilities como contrato** e **Plugins como implementações
intercambiáveis**. Uma *Capability* (ex.: `PORT_DISCOVERY`, `WEB_PROBE`,
`VULN_TEMPLATE_SCAN`) descreve *o que* é feito; um plugin descreve *como*, com
qual ferramenta. Trocar `httpx` por outra ferramenta de `WEB_PROBE` não pode
afetar nada acima da camada de plugin.

- O **pipeline referencia capabilities**, não nomes de ferramenta
  (`engine/pipeline.py`).
- O **registry faz auto-discovery** varrendo `metadata.yaml` de cada plugin
  (`engine/registry.py`). O Core **nunca muda** para adicionar um plugin —
  adicionar ferramenta = criar uma pasta.
- Um plugin declara **uma ou mais** capabilities (`nmap` provê
  `PORT_DISCOVERY`, `SERVICE_DETECTION`, `HOST_DISCOVERY`).
- O `BaseToolPlugin` mantém a execução segura já existente (lista de args,
  `shell=False`, timeout) herdada do antigo `BaseToolAdapter`.

## Contrato do plugin

```
plugins/<red|blue|purple>/<nome>/
  metadata.yaml   # capability(ies), categoria, perspectivas, ferramenta+versão
                  # (# VERIFICAR), licença, commercial_use, requires_credentials,
                  # chained_after, enabled_by_default
  runner.py       # classe BaseToolPlugin: build_args + execução segura
  parser.py       # normaliza a saída bruta → schema Finding
  ai.py           # enriquecimento por IA (OPCIONAL) — com fallback determinístico
  tests/          # unit + fixtures de saída real da ferramenta
  docs/           # o que faz, entrada/saída, exemplos
```

## Consequências

- **+** Extensibilidade real; Core estável; ferramentas testáveis isoladas.
- **+** Metadados declarativos resolvem ativação (perspectiva/licença) sem `if`
  espalhado.
- **−** Discovery dinâmico exige carga por `importlib` — mitigado com
  isolamento de falha (um plugin quebrado não derruba o registry) e testes.
- **Compatibilidade:** os 6 adapters existentes foram migrados 1:1 para plugins;
  a cobertura de parser foi preservada em `plugins/*/tests/`.
