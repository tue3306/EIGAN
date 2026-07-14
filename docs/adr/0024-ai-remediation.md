# ADR-0024 — Remediação por IA (plano estruturado o-que/como)

- **Status:** aceito (retroativo — decisão já implementada)
- **Data:** 2026-07-14
- **Relacionado:** CLAUDE.md §7 (a IA produz inteligência), §12 (relatórios),
  ADR-0010 (provedores de IA), ADR-0016 (prompt injection)

## Contexto

Além de listar findings, o produto precisa dizer **o que arrumar e como**,
priorizado. Isso é trabalho de inteligência (correlação + priorização), não de
serialização determinística.

## Decisão

`ai/remediation.py`: a partir do contexto do scan (findings grounded + neutralizados
contra prompt-injection, ADR-0016), a IA produz um **plano JSON estruturado** —
`items[{title, asset, severity, what, how, priority, effort}]` + `summary` — validado
(Pydantic v2), com **fallback textual** em erro. Gerado **automaticamente** ao fim do
scan e persistido na coluna `scans.ai_remediation`; `GET/POST /scans/{id}/remediation`
servem/regeram; exibido no dashboard (painel 🛠️) e nos relatórios PDF/HTML/MD. Marcado
`ai_generated`. Baseia-se **só** nos findings (§3.1 — não inventa CVE/versão/score).

## Consequências

- **Positivas:** remediação acionável e priorizada, auto e reproduzível no store;
  degrada sem quebrar (fallback textual) e nunca aplica nada sozinha (revisável, como
  os playbooks Ansible do `eigan remediate`).
- **Custos:** exige um provedor de IA (AI-native, §3.4) — coerente com o produto.
