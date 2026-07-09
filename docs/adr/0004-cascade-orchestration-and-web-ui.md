# ADR-0004 — Orquestração em cascata dirigida por descoberta + interface web

- **Status:** aceito
- **Data:** 2026-07-09
- **Relaciona-se com:** [ADR-0001](0001-plugin-capability-architecture.md)
  (capabilities), [ADR-0003](0003-plugins-directory-layout.md) (layout de plugin)

## Contexto

O MVP executa um pipeline determinístico por *capability/perspectiva*
(`engine/pipeline.py`). Faltavam duas coisas para o produto virar uma plataforma
usável por não especialistas:

1. **Cascata dirigida por descoberta** — "encontrou a porta 445 (SMB) ⇒ rode
   `enum4linux` + `cme_smb_recon`", sem o usuário digitar nada. O pipeline
   fixo por estágio não expressava esse acoplamento condicional.
2. **Interface web** — dashboard + wizard + progresso em tempo real, para que o
   usuário final **não toque a linha de comando**.

Restrições inegociáveis do CLAUDE.md que moldaram a decisão:

- A IA **não** decide nem executa scanner (§3.3); toda detecção é determinística.
- Autorização (consent gate) sempre presente, nunca removida (§2).
- Core intacto ao somar plugin; decisão via metadados, não `if` no fluxo (§6).
- "Baixa e roda": zero build step obrigatório (§13).

## Decisão

### 1. Grafo de cascata declarativo (`triggers_on` no `metadata.yaml`)

Cada plugin declara regras `triggers_on`: condições sobre um `Finding`
normalizado (porta, serviço, severidade mínima, substring de título, ferramenta
de origem) e a lista `then_execute`. O casamento é **lógica pura**
(`engine/cascade.py` → `CascadeGraph`), não IA. Cada disparo carrega uma
**justificativa legível** para log e UI ("sem mágica").

Consequências: adicionar/alterar cascata = editar YAML, sem tocar o Core;
regras casam por porta/serviço, então valem para qualquer ferramenta que proveja
a descoberta (capabilities, não ferramentas).

### 2. `CascadeOrchestrator` como camada acima do Core

`engine/cascade_orchestrator.py` envolve o `Orchestrator` determinístico via um
**observer opcional** (porta do domínio: o Core não conhece cascata/eventos).
A cada lote de findings ele consulta o grafo, transmite eventos e executa uma
**segunda onda** (profundidade 1, bounded) com as ferramentas disparadas que
estão disponíveis e ainda não rodaram. Ferramentas roadmap/indisponíveis são
registradas honestamente como *sugeridas, não executadas*. Persistência num
único ponto (dedup → risco → grava), evitando scan meio-gravado.

### 3. Streaming por `EventSink` (porta) + `ScanManager` (infra)

`engine/events.py` define o formato único de evento e a porta `EventSink`. A API
(`api/scan_manager.py`) fornece a implementação concreta: roda o scan numa thread
daemon e mantém um **buffer de eventos protegido por lock**, lido pelo handler
async. Optou-se por buffer + polling curto no WebSocket em vez de
`loop.call_soon_threadsafe` — mais simples e robusto, sem malabarismo de event
loop entre threads. Endpoint de polling (`/progress?since=`) é o fallback do WS.

### 4. Interface: SPA vanilla, sem build step

O prompt sugeria React/Vue/Svelte. **Divergimos** e usamos JavaScript vanilla
servido de `api/static/` (roteador por hash, componentes como funções). Motivo
(precedência §4/§13 do CLAUDE.md): "baixa e roda" e zero-config vencem a
conveniência de um framework que exigiria toolchain Node, build e artefatos —
atrito incompatível com o requisito de instalação trivial. Um design system em
CSS com tokens únicos cobre tema claro/escuro. A regra de negócio fica 100% na
API; o frontend só renderiza.

## Alternativas consideradas

- **Cascata dentro do `Orchestrator`**: acoplaria o Core à cascata e a eventos,
  violando §6. Rejeitado em favor do observer/porta.
- **Reescrever o pipeline como grafo dinâmico puro**: jogaria fora a ordenação
  determinística por estágio (previsível e testável). A cascata como *camada*
  preserva ambos: pipeline previsível + expansão dirigida por descoberta.
- **Frontend em React**: rejeitado pelo custo de build/toolchain (§13).
- **WebSocket via fila async cross-thread**: mais "elegante", porém frágil;
  buffer+polling é suficiente e à prova de reconexão.

## Consequências

- ✅ Core inalterado; cascata e UI são camadas externas.
- ✅ Cada disparo é auditável (log justificado) — requisito "sem mágica".
- ✅ Consent gate preservado na API (POST recusa sem `authorized`).
- ✅ Sem toolchain de frontend; `vulnforge serve` já entrega a UI completa.
- ⚠️ Segunda onda é profundidade 1 por enquanto (evita recursão não-limitada);
  cascatas multi-nível são trabalho futuro com guarda de profundidade/orçamento.
- ⚠️ Muitas ferramentas de cascata (`enum4linux`, `cme`, ...) ainda são roadmap:
  aparecem como *sugeridas* até serem construídas (scaffold honesto).
