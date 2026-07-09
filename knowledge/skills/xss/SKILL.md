---
name: cross-site-scripting
description: Detecção e remediação de Cross-Site Scripting (XSS).
domain: web
subdomain: injection
tags: [owasp, xss, injection]
cwe: CWE-79
owasp: "A03:2021"
mitre_attack: T1059
nist_csf: PR.DS
---

# When to Use
Quando entrada do usuário é refletida ou armazenada e renderizada sem
codificação, permitindo execução de script no navegador da vítima (roubo de
sessão, phishing, ações não autorizadas).

# Prerequisites
- Aplicação web dentro do escopo autorizado.

# Workflow
1. Mapear pontos de reflexão (parâmetros, campos armazenados, DOM sinks).
2. Injetar marcadores inertes para confirmar reflexão sem codificação.
3. Classificar tipo: refletido, armazenado ou baseado em DOM.

# Verification
Confirme que a saída é codificada por contexto (HTML/atributo/JS/URL) e que a
CSP bloqueia scripts inline.

# Remediation
Codifique a saída conforme o contexto de renderização; prefira frameworks que
escapam por padrão. Implemente Content-Security-Policy restritiva, use flags
HttpOnly/Secure em cookies e valide entrada por allow-list. Referência: OWASP
XSS Prevention Cheat Sheet.
