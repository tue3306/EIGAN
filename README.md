<p align="center">
  <img src="web/assets/logo.svg" alt="VulnForge" height="72">
</p>

<p align="center">
  <strong>Plataforma modular de operações de segurança — Red · Blue · Purple.</strong><br>
  Core Engine próprio, arquitetura de plugins, <strong>funciona offline e sem chave de IA</strong>.
</p>

<p align="center">
  <a href="LICENSE"><img alt="Licença" src="https://img.shields.io/badge/licen%C3%A7a-Apache--2.0-blue"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-3776ab">
  <a href="https://github.com/tue3306/vulnerability-scanner/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/tue3306/vulnerability-scanner/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="IA opcional" src="https://img.shields.io/badge/IA-opcional-6c5ce7">
</p>

---

> ## ⚠️ AVISO LEGAL — USO AUTORIZADO APENAS
>
> Scanning ativo de vulnerabilidades **sem autorização documentada é ilegal** em
> muitas jurisdições. O VulnForge **bloqueia por padrão** qualquer alvo fora de um
> `scope.yaml` autorizado e exige confirmação de autorização. Você é o único
> responsável por operar **apenas** contra sistemas que possui ou tem permissão
> escrita para testar. Testes de integração rodam somente contra alvos
> vulneráveis **locais** (DVWA/Juice Shop), nunca contra terceiros.

## ⚡ Quickstart (3 minutos)

```bash
# 1. instalar (Python 3.11+)
pip install -e ".[pdf,dev]"

# 2. checar o ambiente (ferramentas, IA, Docker, feeds) — veredito claro
vulnforge doctor

# 3. subir um alvo de teste LOCAL que você controla (exemplo)
docker run --rm -d -p 3000:3000 bkimminich/juice-shop

# 4. wizard: alvo → perspectiva → autorização inline → progresso → PDF
vulnforge

# 5. dashboard web
vulnforge serve            # http://127.0.0.1:8000
```

Sem nenhuma chave de API, **tudo acima funciona** — a IA só enriquece quando presente.

## 🗺️ Mapa do projeto

```
src/vulnforge/       Core: domínio, engine, análises, report, IA, API, CLI
plugins/             Capabilities intercambiáveis (red/ blue/ purple/) — auto-discovery
config/              profiles.yaml · tools.yaml · ai.yaml (zero-config por padrão)
knowledge/           Base determinística: skills/ (SKILL.md), attack/, compliance/
web/                 Landing page + design tokens + logo/favicon
docs/                architecture · adr/ · design/ · roadmap/ · AUDIT · BLOCKERS
examples/            Alvos de exemplo + laboratório local
docker/              Dockerfile + compose (sandbox das ferramentas)
tests/               Unit + integração (só contra alvos locais)
```

Cada diretório tem seu próprio `README.md`.

## O que é (e o que não é)

O VulnForge não é "só um scanner": é uma **plataforma** com **Core Engine
próprio** que orquestra ferramentas, **normaliza** os resultados em um schema
único, **correlaciona** entre fontes, **prioriza risco** (CVSS/EPSS/KEV) e
**gera relatórios** — extensível por **plugins** e pensada para crescer a 100+
módulos sem reescrever o núcleo. É **AI-native por design e AI-opcional por
requisito**.

Tudo gira em torno de duas perguntas:

- **Outside-In** — o que um atacante descobre vindo de fora?
- **Inside-Out** — o que um analista identifica estando dentro da rede?

## Diferenciais

- 🧩 **Plugins/capabilities** — adicionar uma ferramenta é criar uma pasta; o
  Core não muda (auto-discovery por `metadata.yaml`).
- 🧭 **Perspectiva de 1ª classe** — Outside-In/Inside-Out dirigem guardrails,
  ferramentas e rate limit por configuração, não por `if` espalhado.
- 🎯 **Risk Engine honesto** — CVSS v3.1/v4, EPSS (FIRST.org) e CISA KEV de fonte
  oficial; sinal não confirmado sai `UNVERIFIED`, **nunca** fabricado.
- 🔗 **Correlação + inventário + ATT&CK** — dedup entre ferramentas por ativo,
  mapa MITRE e gap analysis, sem fundir perspectivas cegamente.
- 📄 **Relatórios** técnico e executivo em **HTML/PDF/JSON/CSV/SARIF** — todos
  sem IA, com hash de integridade e metodologia (PTES/NIST 800-115).
- 🤖 **IA opcional** multi-provedor (Anthropic/OpenAI/Google/Ollama) com
  **fallback determinístico** e grounding; explica e prioriza, jamais escaneia.
- 🚀 **Baixa e roda** — wizard, `doctor`, consent inline e zero-config.

## Arquitetura

```
Interfaces:  CLI & Wizard  ·  API REST + WebSocket  ·  Dashboard  ·  Landing
      │
Core Engine: Discovery → Fingerprint → Execução (plugins) → Normalização
             → Correlação → Enriquecimento (ATT&CK·CVSS·CWE·CAPEC·EPSS/KEV)
             → Risco → Reporting                                    ← núcleo estável
      │
Infra:  plugins (red/blue/purple)  ·  Store (SQLite/Postgres)
        ·  Relatórios (PDF/HTML/JSON/CSV/SARIF)  ·  IA (opcional, com fallback)
```

Dependências apontam para dentro: o domínio (`findings/`, `security/`,
`perspective.py`) não conhece banco, rede nem ferramentas. Detalhes em
[docs/architecture.md](docs/architecture.md) e nos [ADRs](docs/adr/).

## Tecnologias

Python 3.11+ · Pydantic v2 (schema) · SQLite via stdlib (Repository Pattern,
Postgres opcional via `DATABASE_URL`) · Click (CLI) + wizard · FastAPI + Uvicorn
(API/WS) · Jinja2 + WeasyPrint (PDF) · pytest · ruff · mypy.

## Instalação

```bash
git clone https://github.com/tue3306/vulnerability-scanner.git
cd vulnerability-scanner
pip install -e ".[pdf,dev]"        # extras: pdf, ai, dev
```

Ferramentas externas (nmap, nuclei, subfinder, ...) são detectadas no PATH;
adapters indisponíveis são **pulados com aviso** (não quebram o scan). `vulnforge
doctor` diz exatamente o que falta e como instalar. Caminho recomendado com
sandbox: [docker/](docker/) (`docker compose up`).

## Uso

```bash
# escopo: copie e edite com APENAS os seus alvos autorizados
cp scope.example.yaml scope.yaml

# scan determinístico (sem IA) — escolha a perspectiva
vulnforge scan app.local --perspective external --profile standard --scope scope.yaml
vulnforge scan 10.0.0.5   --perspective internal --profile standard --scope scope.yaml

# relatório (sem nenhuma chave de API); estilos: technical | executive
vulnforge report --scan 1 --format pdf --style executive

# API + dashboard
vulnforge serve                    # http://127.0.0.1:8000  (/docs, /api/v1/...)

# CI: falha o pipeline se houver finding alto
vulnforge scan --target-list examples/targets.example.txt --profile web-only \
  --scope scope.yaml --yes --fail-on high
```

Perfis: `quick`, `standard`, `deep`, `network-only`, `web-only`. Mais exemplos e
laboratório local em [examples/](examples/).

## Camada de IA (opcional)

Sem chave, tudo funciona via fallback determinístico (base de conhecimento em
`knowledge/skills/`). Com uma chave (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
`GOOGLE_API_KEY`) ou Ollama local (`OLLAMA_HOST`), o sumário executivo e as
explicações são enriquecidos e marcados `ai_generated`. Configure em
`config/ai.yaml` (chaves só por env — nunca no arquivo). A IA **nunca** escaneia
nem descobre vulnerabilidade: só interpreta findings já produzidos.

## Screenshots

A landing page ([`web/index.html`](web/index.html)) traz uma prévia do dashboard
com a identidade visual do produto. O dashboard real sobe com `vulnforge serve`.

> 📸 _GIFs/screenshots animados do wizard e do dashboard entram aqui em uma
> próxima iteração (placeholder)._ Para vê-los agora, rode `vulnforge serve` ou
> abra a landing localmente (`python -m http.server -d web 5500`).

## FAQ

**Preciso de uma chave de IA?** **Não.** O VulnForge funciona 100% sem IA —
scans, correlação, risco, dashboard e relatórios completos saem do caminho
determinístico. A IA só adiciona riqueza quando há um provedor configurado.

**É legal usar?** Depende de **você** ter autorização. Só escaneie o que você
possui ou tem permissão escrita para testar. O produto bloqueia alvos fora do
escopo por padrão — trate isso como recurso, não obstáculo. Veja o
[SECURITY.md](SECURITY.md) e o aviso legal acima.

**Como adiciono uma ferramenta?** Criando uma pasta em `plugins/` — o Core faz
auto-discovery. Passo a passo no [CONTRIBUTING.md](CONTRIBUTING.md).

Mais perguntas na seção FAQ da [landing page](web/index.html).

## Roadmap

MVP entregue (Red/Blue/Purple), módulos futuros como *scaffold honesto* e a visão
de plataforma estão em [docs/ROADMAP.md](docs/ROADMAP.md). Itens comerciais são
**apenas documentados** em [docs/roadmap/commercial.md](docs/roadmap/commercial.md)
(sem código).

## Contribuindo

Contribuições são bem-vindas! Veja [CONTRIBUTING.md](CONTRIBUTING.md) (inclui
"adicionar um plugin em ~5 min" e a Definition of Done) e o
[Código de Conduta](CODE_OF_CONDUCT.md). Mudanças de comportamento vêm com teste;
`ruff` + `mypy` + `pytest` verdes antes do PR.

## Licença

[Apache-2.0](LICENSE) — © 2026 VulnForge contributors.
