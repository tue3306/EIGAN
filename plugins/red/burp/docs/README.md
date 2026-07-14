# burp — Burp Suite Professional/Enterprise (scaffold honesto, PAGO)

**Estado:** `roadmap: true`, `licensing: paid`. Descoberto pelo registry e
mostrado no `eigan doctor`, mas **não executa** — é uma ferramenta **comercial e
centrada em GUI**.

## Por que não é automatizada

Burp Suite Professional é licenciado e opera primariamente por interface gráfica.
A automação headless só é viável via:

- **Burp Suite Enterprise Edition** + sua **REST API** (`BURP_API_KEY` + endpoint
  do servidor Enterprise), ou
- a **Extender/Montoya API** dentro de uma instância licenciada.

Ambos exigem **licença comercial**. Por isso o EIGAN **declara** a ferramenta (para
transparência de cobertura — o operador vê que existe um DAST comercial fora do
arsenal automatizado), mas **nunca finge executá-la** (CLAUDE.md §3.6).

## Alternativas open-source já ativas no EIGAN

Para DAST/varredura ativa de web sem licença, o arsenal Red já cobre: `nuclei`
(templates), `nikto` (`web_server_scan`), `dalfox` (XSS), `sqlmap` (SQLi),
`ffuf`/`feroxbuster` (conteúdo) e o `exposure` prober (segredos/arquivos vazados).

## O que falta para tornar real (roadmap)

1. Runner que fale com a REST API do Burp Suite Enterprise (lista de args/HTTP
   seguro, nunca `shell=True`; chave só por env, nunca ecoada).
2. Parser que normalize os *issues* do Burp para o schema de `Finding`.
3. Fixtures de saída real da API + testes marcados roadmap.
