# Processo de Release — EIGAN

Este documento descreve como uma versão do EIGAN é preparada e publicada.
Versionamento: [SemVer](https://semver.org/lang/pt-BR/). Changelog:
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) em [CHANGELOG.md](CHANGELOG.md).

## Checklist de release

1. **Verde local e na CI:** `ruff check`, `ruff format --check`, `mypy src`,
   `pytest` (ver `.github/workflows/ci.yml`).
2. **Instalação limpa** (`smoke-install`): `pip install .` → `eigan --version`,
   `eigan doctor`, `eigan plan … --dry-run` sem erro.
3. **Versão sincronizada:** `pyproject.toml` (`version`) e
   `src/eigan/__init__.py` (`__version__`) — fonte única, sem drift.
4. **CHANGELOG** atualizado com a seção da versão (data + Added/Changed/Fixed).
5. **Docs** refletem o estado real (README, `docs/`, ADRs).
6. **Tag anotada** `vX.Y.Z` e push:
   ```bash
   git tag -a vX.Y.Z -m "EIGAN vX.Y.Z — <resumo>"
   git push origin main --follow-tags
   ```
7. **GitHub Release** a partir da tag (notas = seção do CHANGELOG).
8. **PyPI** (quando o *trusted publisher* estiver configurado pelo dono):
   `.github/workflows/publish.yml` dispara no GitHub Release (OIDC, sem segredo
   no repo). Ver `docs/BLOCKERS.md` #5.

## Notas da v1.0.0 — 2026-07-11

Primeiro release estável. Destaques:

- **Agente de segurança AI-native**: a IA **comanda** o scan de ponta a ponta
  (planeja, escolhe as capacidades, reage às descobertas e narra) — sem um
  provedor de IA configurado, o scan é recusado com um erro acionável (ADR-0012).
  Independente de provedor: Anthropic, OpenAI, Gemini, OpenRouter, Groq, Together,
  Azure OpenAI e **Ollama local** (privacidade/offline).
- **Cascata adaptativa entre ferramentas**: descobertas encadeiam os próximos
  passos (ex.: nmap acha Samba/445 → enum4linux + volta ao nmap com scripts NSE).
- **Núcleo cognitivo** (`AgenticPlanner`) com timeline de raciocínio em tempo real
  no dashboard; **Policy/Guardrail Engine** determinístico (`ImpactClass`).
- **Segurança inegociável**: gate de autorização/escopo, execução segura (lista de
  args, nunca `shell=True`), redaction de segredos/PII, grounding/anti-invenção.
- **Saídas**: HTML/PDF/JSON/CSV/SARIF (exportações determinísticas; narrativas por IA).
- Renome **VulnForge → EIGAN**; `ruff` + `mypy` + `pytest` verdes.

Ação pendente do dono: renomear o repositório no GitHub para `eigan`
(Settings → Rename) — ver `docs/BLOCKERS.md` #6.
