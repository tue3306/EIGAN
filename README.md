# VulnForge

Plataforma modular de **scanning e gestão de vulnerabilidades para Linux** —
estilo OpenVAS/Greenbone + OWASP ZAP, unificada, com uma **camada opcional de
IA** para leitura e explicação dos resultados. O núcleo (engine + store +
relatório) funciona **100% sem IA e offline**.

---

> ## ⚠️ AVISO LEGAL — USO AUTORIZADO APENAS
>
> Scanning ativo de vulnerabilidades **sem autorização documentada é ilegal** em
> muitas jurisdições. Esta ferramenta **bloqueia por padrão** qualquer alvo que
> não esteja declarado em um `scope.yaml` com `authorized: true`. Você é o único
> responsável por operar exclusivamente contra sistemas que tem permissão
> explícita e por escrito para testar. Testes de integração rodam apenas contra
> alvos vulneráveis **locais** (DVWA/Juice Shop), nunca contra terceiros.

---

## Princípios de arquitetura

- **Determinístico primeiro (CLAUDE.md §7):** toda função de IA tem um caminho
  equivalente que roda sem nenhuma chave de API. A IA apenas *lê e explica*
  findings já produzidos pelo engine — nunca escaneia sozinha.
- **Guardrail de escopo é parte do produto**, não um extra: `security/scope.py`
  + consent gate bloqueiam alvos fora do escopo.
- **Anti-invenção (CLAUDE.md §5):** versões de ferramentas e CVEs não são
  fixados "de memória" — ficam marcados `VERIFICAR`/`UNVERIFIED` até confirmação
  contra fonte oficial (NVD/OSV).
- **Findings normalizados:** schema único para toda ferramenta; dedup e
  correlação entre fontes.
- **Camadas desacopladas:** domínio (findings/scope) sem I/O; adapters, store,
  IA e report implementam portas.

## Stack

Python 3.11+ · Pydantic v2 (schema) · SQLite via stdlib (Repository Pattern,
Postgres opcional) · Click (CLI) · FastAPI + Uvicorn (API/WS) · Jinja2 +
WeasyPrint (PDF) · pytest.

## Instalação (dev)

```bash
pip install -e ".[pdf,dev]"      # ou: pip install -e .
```

Ferramentas externas (nmap, nuclei, ...) são detectadas no PATH; adapters
indisponíveis são pulados com aviso (não quebram o scan). Ver `docker/` para o
caminho recomendado com sandbox.

## Uso

```bash
# 1. copie e edite o escopo (só alvos autorizados!)
cp scope.example.yaml scope.yaml

# 2. scan determinístico (sem IA)
vulnforge scan --target 127.0.0.1 --profile standard --scope scope.yaml

# 3. relatório PDF sem nenhuma chave de API
vulnforge report --scan 1 --format pdf

# 4. API + dashboard
vulnforge serve            # http://127.0.0.1:8000  (/docs, /api/v1/...)

# CI: falha o pipeline se houver finding alto
vulnforge scan --target-list targets.txt --profile web-only \
  --scope scope.yaml --yes --fail-on high
```

Perfis: `quick`, `standard`, `deep`, `network-only`, `web-only`.

## Camada de IA (opcional)

Sem chave configurada, tudo funciona via fallback determinístico (base de
conhecimento em `knowledge/skills/`, padrão agentskills.io). Com uma chave
(`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`) ou Ollama local
(`OLLAMA_HOST`), o sumário executivo e as explicações são enriquecidos e
marcados `ai_generated`. Configuração em `config/ai.yaml`.

## Testes

```bash
pytest -q          # 21 testes: escopo, schema, dedup, store, parsers, report
```

## Status do projeto (roadmap por fases)

Implementado nesta fundação: guardrail de escopo + consent gate, schema de
finding, store SQLite, `BaseToolAdapter` + adapters nmap/nuclei, orquestrador
com dedup, base de conhecimento, relatório determinístico HTML/PDF, camada de IA
com fallback, API REST + esqueleto de dashboard, CLI headless com `--fail-on`.

Próximas fases (ver `docs/architecture.md`): mais adapters (ZAP/nikto/trivy/
testssl), dashboard React, provedores de IA concretos, `.deb`/systemd, feeds.

## Licença

Apache-2.0 — ver [LICENSE](LICENSE).
