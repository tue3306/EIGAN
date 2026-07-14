# ADR-0014 — Autenticação da API/dashboard + bind seguro + consent auditado

- **Status:** aceito
- **Data:** 2026-07-14
- **Relacionado:** CLAUDE.md §2 (consent nunca removido), §4 (#2 segurança do
  produto), §5 (secure coding), §18 (dashboard como porta de entrada), ADR-0011
  (Policy Engine), ADR-0013 (credenciais de ferramenta)

## Contexto

A API (`api/app.py`) e o dashboard **não tinham autenticação alguma** — nenhum
`Depends`/token/middleware. O consent gate era apenas `authorized: bool` no corpo
do `POST /scans` (o próprio cliente marcava `true`). O Docker fazia bind em
`0.0.0.0`. Consequência: **qualquer um que alcançasse a porta** disparava scans
ativos contra alvos arbitrários **a partir da máquina do operador** (transformando
o host numa plataforma de ataque) e lia **todos os findings** (que podem conter
segredos). Numa ferramenta de segurança isso é gravíssimo e fere §4 (#2) e §2.

## Decisão

**Token compartilhado obrigatório + bind loopback por padrão + consent auditado.**

- **Token** (`security/apitoken.py`): `EIGAN_API_TOKEN` no ambiente vence; senão um
  token é gerado (`secrets.token_urlsafe(32)`) e persistido em
  `~/.config/eigan/api_token` (`chmod 600`, nunca commitado/ecoado). Comparação em
  tempo constante (`secrets.compare_digest`).
- **Middleware HTTP**: todo `/api/v1/*` (exceto `/api/v1/health`) exige o token via
  `Authorization: Bearer …`, `X-EIGAN-Token`, ou `?token=` (este último para
  downloads/navegações e o WebSocket, que não setam header). Sem token → **401**.
- **WebSocket**: exige `?token=`; recusa antes do `accept` com código 1008.
- **Bind seguro**: `serve` liga em `127.0.0.1` por padrão. `serve --expose` (ou o
  Docker) liga em `0.0.0.0` e **imprime o token** no log; a API então **exige** o
  token para tudo.
- **Injeção no dashboard só em modo local**: quando NÃO exposto (loopback), o `/`
  injeta `window.__EIGAN_TOKEN__` para o SPA usar sem fricção. Cross-origin não
  consegue **ler** esse HTML (same-origin policy), então o token não vaza para uma
  página maliciosa, e um `POST` CSRF sem o token cai em 401. Quando exposto, o `/`
  **não** injeta — o operador cola o token (guardado em `localStorage`).
- **Consent auditado**: `POST /scans` registra a concessão de consent no log
  estruturado (`logger "eigan.consent"`: cliente/alvos/perspectiva/objetivo). O
  gate `authorized` (403 sem ele) e o gate AI-native (428) permanecem.

## Consequências

- **Positivas:** a API deixa de ser um vetor aberto; uso local segue sem fricção
  (token injetado); exposição exige token explícito; trilha de auditoria do consent.
- **Custos:** o token via `?token=` pode aparecer em logs de acesso — aceitável num
  alvo local e restrito a downloads/WS; o caminho preferencial é o header.
- **Fora de escopo (roadmap):** rate limiting fino, CORS por origem configurável,
  usuários/RBAC, rotação de token. A base de CORS já é segura (sem `Access-Control-
  Allow-Origin` permissivo, o browser bloqueia leituras cross-origin por padrão).
