# plugins/ — Capabilities intercambiáveis

Aqui moram os **plugins** do EIGAN, organizados por domínio
(`red/`, `blue/`, `purple/`). O Core Engine faz **auto-discovery** por
`metadata.yaml` — **adicionar um plugin não toca o Core** (ADR-0001/0003).

## Conceito: capability, não ferramenta

Uma *capability* é o contrato (ex.: `port_discovery`); ferramentas são
implementações intercambiáveis (naabu, nmap, masscan). Trocar a ferramenta não
pode quebrar nada acima da camada de plugin.

## Anatomia de um plugin

```
plugins/<red|blue|purple>/<nome>/
  metadata.yaml   # contrato: capabilities, perspectivas, ferramenta+versão
                  # (# VERIFICAR), licença, commercial_use, install_hint, ...
  runner.py       # executa (subprocess seguro: lista de args, NUNCA shell=True)
  parser.py       # normaliza a saída para o schema único de Finding
  ai.py           # enriquecimento por IA OPCIONAL, com fallback determinístico
  tests/          # unit + fixtures de saída REAL da ferramenta
  docs/  requirements.txt
```

## Categorias e estado

- **red/** (Outside-In / Inside-Out): `subfinder`, `dnsx`, `naabu`, `nmap`,
  `httpx`, `nuclei` **executam**; `active-directory`, `cloud`, `wireless`,
  `password-audit`, `exploitation` são **scaffold** (`roadmap: true`).
- **blue/**: MVP de análise no Core (inventário/conformidade/risco);
  `siem`, `detection-rules`, `threat-hunting`, `malware-analysis`,
  `log-analysis`, `incident-response` são **scaffold**.
- **purple/**: mapa ATT&CK + gap no Core; `attack-simulation`,
  `detection-validation`, `control-validation` são **scaffold**.

**Scaffold honesto ≠ stub falso:** o módulo é descoberto e listado em
`eigan doctor`, mas **não finge executar** até ser implementado.

## Adicionar um plugin

Passo a passo (≈5 min) no [CONTRIBUTING.md](../CONTRIBUTING.md#adicionar-um-plugin-em-5-minutos).
Contrato e pipeline: [docs/architecture.md](../docs/architecture.md).
