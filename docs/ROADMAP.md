# Roadmap

O EIGAN cresce por **plugins/capabilities** (ADR-0001): adicionar um módulo é
criar uma pasta em `plugins/<categoria>/<nome>/` — o Core não muda. Os módulos
abaixo já têm o **contrato declarado** (metadata + capability) como *scaffold
honesto* (`roadmap: true`): são descobertos pelo registry e aparecem em
`eigan doctor`, mas **não executam** até serem implementados.

## Entregue (MVP)

- **Red:** Recon (subfinder, dnsx), Network (naabu, nmap, **enum4linux** para
  SMB/Samba, **nmap-nse** para 2ª onda com scripts NSE), Web (httpx, nuclei) —
  Outside-In e Inside-Out por perspectiva.
- **Cascata adaptativa entre ferramentas (ADR-0004):** descobertas encadeiam os
  próximos passos automaticamente — ex.: nmap/naabu acham 445/Samba → **enum4linux**
  (usuários/shares) + **nmap-nse** (scripts smb-vuln); share gravável → volta ao
  nmap-nse; serviço web → whatweb/nuclei; WordPress → wpscan.
- **Blue REAL (ADR — Blue Engine):** `log-analysis` (nativo) detecta ataques em
  logs (força-bruta SSH/T1110, web/T1190, varredura/T1595, sudo/T1548) citando as
  linhas reais; agente `blue-detection` (built); comando **`eigan blue <logs>`** e
  endpoint **`POST /api/v1/blue`** (upload de conteúdo). + Inventário de ativos,
  Conformidade indicativa (CWE→OWASP/NIST), postura de risco (dashboard/relatório).
- **Purple REAL:** `analysis/purple.py` correlaciona técnicas ATT&CK atacadas (Red)
  × detectadas (Blue) → cobertura % e **pontos cegos**; **`eigan purple`**, `POST
  /api/v1/purple` + view no dashboard. + Mapa MITRE ATT&CK dos findings.
- **Red — exposição/"dados vazados":** `exposure` prober (nativo, blindado contra
  SSRF) sonda `.git`/`.env`/backups/chaves/segredos embutidos (mascarados).
- **Expansão de alvos dirigida por descoberta (ADR-0018):** o agente escaneia o que
  a recon acha (subdomínio→IP→portas→web), sob gate de escopo + teto.
- **Policy Engine no loop (ADR-0011 Fase 3):** cada ação ativa arbitrada (executar/
  HITL/recusar). **Auth da API + SSRF + anti prompt-injection** (ADR-0014/15/16).
- **Engine:** Correlação por ativo + Risk Engine (CVSS/EPSS/KEV com `UNVERIFIED`).
- **Agente autônomo — Núcleo Cognitivo (ADR-0007/0009):** `AgenticPlanner` — a IA
  **comanda** o scan (planeja + replaneja por onda, saída validada Pydantic v2,
  grounded no registry) sobre o loop `Goal→Plano→Seleção→Execução→Feedback→replan→
  Stop`, com **Agente Recon real** (Web + Infra), Tool Selection Engine
  determinístico e **fallback determinístico** (cascata como piso). Timeline de
  raciocínio em tempo real na UI. CLI `eigan plan`.
- **Memória entre scans (Pilar 2 / ADR-0008):** diff determinístico
  (novos/corrigidos/persistentes + novos ativos/serviços). CLI `eigan diff`.
- **Auto Remediation (Pilar 6 / ADR-0008):** playbooks Ansible revisáveis a partir
  do finding (nunca auto-aplicados). CLI `eigan remediate`.
- **Saídas:** HTML/PDF/JSON/CSV/SARIF, técnico e executivo.

> Visão dos **10 pilares** da plataforma autônoma (status real × scaffold de cada
> um): ver [ADR-0008](adr/0008-agent-platform-ten-pillars.md).

## Scaffolded (roadmap — contrato declarado, ainda não executa)

| Categoria | Módulo | Capability |
|---|---|---|
| Cognitivo | Agentes Web/Cloud/AD/Exploitation | especialidade (`built=false`) |
| Red/Web | whatweb, wpscan, feroxbuster, katana | `cms_scan` / `web_crawl` |
| Red/Web | testssl (TLS), sqlmap (gated) | `tls_assessment` / `exploitation` |
| Red/Net | ldapsearch (LDAP/AD) | `ad_enumeration` |
| Red | Active Directory | `ad_enumeration` |
| Red | Cloud (Azure/AWS/GCP) | `cloud_audit` |
| Red | Wireless | `wireless_audit` |
| Red | Password Audit | `password_audit` |
| Red | Exploitation (autorizada) | `exploitation` |
| Blue | SIEM | `siem_ingest` |
| Blue | Detection Rules (Sigma) | `detection_rules` |
| Blue | Threat Hunting | `threat_hunting` |
| Blue | Malware Analysis | `malware_analysis` |
| Blue | Incident Response | `incident_response` |
| Purple | Attack Simulation | `attack_simulation` |
| Purple | Detection Validation | `detection_validation` |
| Purple | Control Validation | `control_validation` |

## Plataforma (futuro)

- Fila distribuída (Celery/RQ + Redis) trocável pela fila em processo.
- Postgres via `DATABASE_URL` (Repository Pattern já desacopla).
- Comercial (portal/billing/multi-tenant): **apenas planejado** —
  ver [commercial.md](roadmap/commercial.md), sem código nesta fase.
