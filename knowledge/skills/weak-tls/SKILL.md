---
name: weak-tls-configuration
description: Configuração TLS fraca (protocolos/cifras obsoletos, certificados).
domain: network
subdomain: cryptography
tags: [tls, crypto, transport]
cwe: CWE-327
owasp: "A02:2021"
mitre_attack: T1040
nist_csf: PR.DS
---

# When to Use
Quando um serviço aceita protocolos obsoletos (SSLv3, TLS 1.0/1.1), cifras
fracas, ou apresenta certificado inválido/expirado — expondo o tráfego a
interceptação e downgrade.

# Prerequisites
- Host/porta TLS dentro do escopo autorizado.

# Workflow
1. Enumerar protocolos e cifras suportados (ex.: testssl.sh/sslscan).
2. Verificar validade e cadeia do certificado.
3. Identificar suporte a renegociação insegura e compressão.

# Verification
Confirme que apenas TLS 1.2+ e cifras fortes (AEAD) são aceitos e o certificado
é válido e confiável.

# Remediation
Desabilite SSLv2/v3 e TLS 1.0/1.1; habilite TLS 1.2/1.3 com cifras AEAD e
forward secrecy. Renove certificados antes do vencimento e use HSTS. Referência:
Mozilla TLS Configuration Guidelines.
