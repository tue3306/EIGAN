# Plugin: nmap-nse

**Categoria:** red · **Capabilities:** nse_vuln_scan

Segunda onda do nmap com scripts **NSE de vulnerabilidade** (`--script vuln`,
`smb-vuln-*`). Disparado pela cascata quando um serviço/porta relevante é
descoberto (ex.: 445/Samba, share gravável).

## Entrada / Saída
- **Entrada:** host/IP com serviço detectado.
- **Saída:** `Finding`s normalizados (`parser.py`) — vulnerabilidades confirmadas por NSE.

## Requisitos
- Binário externo `nmap` no PATH (com os scripts NSE) ou via sandbox Docker.
- Sem dependências Python adicionais (ver `requirements.txt`).

## Como é executado
O runner monta a lista de argumentos (nunca `shell=True`) e o engine roda em
subprocess com timeout. Rode `eigan doctor` para ver disponibilidade.
