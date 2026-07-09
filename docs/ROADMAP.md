# Roadmap

O VulnForge cresce por **plugins/capabilities** (ADR-0001): adicionar um módulo é
criar uma pasta em `plugins/<categoria>/<nome>/` — o Core não muda. Os módulos
abaixo já têm o **contrato declarado** (metadata + capability) como *scaffold
honesto* (`roadmap: true`): são descobertos pelo registry e aparecem em
`vulnforge doctor`, mas **não executam** até serem implementados.

## Entregue (MVP)

- **Red:** Recon (subfinder, dnsx), Network (naabu, nmap), Web (httpx, nuclei) —
  Outside-In e Inside-Out por perspectiva.
- **Blue:** Inventário de ativos, Conformidade indicativa (CWE→OWASP/NIST),
  postura de risco (dashboard/relatório).
- **Purple:** Mapa MITRE ATT&CK dos findings + gap analysis + relatório executivo.
- **Engine:** Correlação por ativo + Risk Engine (CVSS/EPSS/KEV com `UNVERIFIED`).
- **Saídas:** HTML/PDF/JSON/CSV/SARIF, técnico e executivo.

## Scaffolded (roadmap — contrato declarado, ainda não executa)

| Categoria | Módulo | Capability |
|---|---|---|
| Red | Active Directory | `ad_enumeration` |
| Red | Cloud (Azure/AWS/GCP) | `cloud_audit` |
| Red | Wireless | `wireless_audit` |
| Red | Password Audit | `password_audit` |
| Red | Exploitation (autorizada) | `exploitation` |
| Blue | SIEM | `siem_ingest` |
| Blue | Detection Rules (Sigma) | `detection_rules` |
| Blue | Threat Hunting | `threat_hunting` |
| Blue | Malware Analysis | `malware_analysis` |
| Blue | Log Analysis | `log_analysis` |
| Blue | Incident Response | `incident_response` |
| Purple | Attack Simulation | `attack_simulation` |
| Purple | Detection Validation | `detection_validation` |
| Purple | Control Validation | `control_validation` |

## Plataforma (futuro)

- Provedores de IA concretos (Anthropic/OpenAI/Google/Ollama) plugados no
  `ai/provider.py` (hoje: fallback determinístico + porta pronta).
- Fila distribuída (Celery/RQ + Redis) trocável pela fila em processo.
- Postgres via `DATABASE_URL` (Repository Pattern já desacopla).
- Comercial (portal/billing/multi-tenant): **apenas planejado** —
  ver [commercial.md](roadmap/commercial.md), sem código nesta fase.
