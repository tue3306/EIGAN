# Plugin: nuclei

**Categoria:** red · **Capabilities:** vuln_template_scan

Scanner de vulnerabilidades por templates. CVE/CVSS do template = evidência (UNVERIFIED).

## Entrada / Saída
- **Entrada:** alvo (host, IP, CIDR ou URL, conforme a capability).
- **Saída:** `Finding`s normalizados (`parser.py`), correlacionáveis pelo engine.

## Requisitos
- Binário externo `nuclei` no PATH (ver `metadata.yaml::version_source`) ou via sandbox Docker.
- Sem dependências Python adicionais (ver `requirements.txt`).

## Como é executado
O runner monta a lista de argumentos (nunca `shell=True`) e o engine roda em
subprocess com timeout. Rode `vulnforge doctor` para ver disponibilidade.
