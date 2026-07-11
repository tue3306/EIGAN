# Plugin: subfinder

**Categoria:** red · **Capabilities:** subdomain_enumeration

Enumeração passiva de subdomínios (OSINT). Só perspectiva EXTERNAL.

## Entrada / Saída
- **Entrada:** alvo (host, IP, CIDR ou URL, conforme a capability).
- **Saída:** `Finding`s normalizados (`parser.py`), correlacionáveis pelo engine.

## Requisitos
- Binário externo `subfinder` no PATH (ver `metadata.yaml::version_source`) ou via sandbox Docker.
- Sem dependências Python adicionais (ver `requirements.txt`).

## Como é executado
O runner monta a lista de argumentos (nunca `shell=True`) e o engine roda em
subprocess com timeout. Rode `eigan doctor` para ver disponibilidade.
