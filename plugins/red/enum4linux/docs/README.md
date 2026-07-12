# Plugin: enum4linux

**Categoria:** red · **Capabilities:** smb_enumeration

Enumeração SMB/Samba: usuários, shares, *null session* e domínio. Disparado pela
cascata quando a porta **445/Samba** é descoberta (ex.: por `nmap`/`naabu`).

## Entrada / Saída
- **Entrada:** host/IP com SMB (445) exposto.
- **Saída:** `Finding`s normalizados (`parser.py`) — shares, usuários, null session.

## Requisitos
- Binário externo `enum4linux` no PATH (ver `metadata.yaml::version_source`) ou via sandbox Docker.
- Sem dependências Python adicionais (ver `requirements.txt`).

## Como é executado
O runner monta a lista de argumentos (nunca `shell=True`) e o engine roda em
subprocess com timeout. Rode `eigan doctor` para ver disponibilidade.
