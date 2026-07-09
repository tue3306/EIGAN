# Plugin: naabu

**Categoria:** red · **Capabilities:** port_discovery

Descoberta rápida de portas abertas, antes do nmap.

## Entrada / Saída
- **Entrada:** alvo (host, IP, CIDR ou URL, conforme a capability).
- **Saída:** `Finding`s normalizados (`parser.py`), correlacionáveis pelo engine.

## Requisitos
- Binário externo `naabu` no PATH (ver `metadata.yaml::version_source`) ou via sandbox Docker.
- Sem dependências Python adicionais (ver `requirements.txt`).

## Como é executado
O runner monta a lista de argumentos (nunca `shell=True`) e o engine roda em
subprocess com timeout. Rode `vulnforge doctor` para ver disponibilidade.
