"""Análises pós-scan (camada de aplicação) sobre findings normalizados.

Estes módulos NÃO escaneiam nem descobrem vulnerabilidade — apenas leem e
organizam o que o engine já produziu (inventário, mapa ATT&CK, conformidade),
alimentando relatórios e dashboard. Determinísticos e sem I/O de rede.
"""
