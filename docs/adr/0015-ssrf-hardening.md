# ADR-0015 — Blindagem de SSRF (redirect / metadata / DNS-rebinding)

- **Status:** aceito
- **Data:** 2026-07-14
- **Relacionado:** CLAUDE.md §3.2 (escopo), §4 (#2 segurança do produto), §5
  (secure coding), ADR-0014 (auth da API)

## Contexto

FALHA CRÍTICA de SSRF. O gate de escopo validava o alvo **original**, mas não os
destinos de **redirect** nem o IP **realmente conectado**. O exposure prober usava
`urllib.urlopen`, que **segue redirect por padrão**, com SSL desligado → um alvo
podia redirecionar para `169.254.169.254` (metadata de nuvem → roubo de credencial)
ou para hosts internos, **furando o escopo**. No modo `UNIFIED` (padrão) o guardrail
público×privado é permissivo, agravando o risco.

## Decisão

Um cliente HTTP **blindado** e um bloqueio central de metadata.

- **`security/ssrf.py`** (`safe_get`): a cada salto, resolve o host, **tria todos os
  IPs** (`resolve_and_screen`), e **fixa a conexão no IP validado** (anti-DNS-
  rebinding) com `Host` header preservando o nome. **Não segue redirect
  automaticamente**: lê o `Location`, revalida o destino e só então segue (até
  `max_redirects`). `ip_category`/`screen_ip` classificam metadata/loopback/link-
  local/private/reserved/public.
- **Metadata SEMPRE bloqueado** (169.254.169.254, 100.100.100.100, `fd00:ec2::254`,
  `metadata.google.internal`) — independe da perspectiva ou de `override`.
  Loopback/link-local/RFC1918/ULA/reservado bloqueados quando `allow_private=False`
  (scan externo); liberados em assumed-breach (interno/unificado).
- **Gate central** (`scope.enforce`): bloqueia o metadata **literal** já na entrada
  (sem I/O de DNS — o gate segue puro); a resolução/rebinding fica no cliente HTTP.
- **exposure prober** passa a usar `safe_get`; `allow_private` vem da perspectiva
  (propagada ao runner via `SafeExecution.execute`). Um redirect/DNS para
  metadata/interno proibido é tratado como inacessível — a sonda não vira pivô.

## Consequências

- **Positivas:** redirect/rebinding para metadata/interno fechado de forma
  sistêmica e reutilizável (qualquer cliente HTTP futuro usa `safe_get`); o gate
  central nega metadata sempre. Verificado ao vivo (302→169.254.169.254 recusado).
- **Custos:** `safe_get` reimplementa o mínimo de HTTP sobre `http.client` (sem
  auto-redirect) — mais código que `urlopen`, em troca de controle de segurança.
- **Fora de escopo (roadmap):** aplicar `safe_get` a futuros clientes HTTP (httpx
  probes); cache de resolução; suporte a proxy.
