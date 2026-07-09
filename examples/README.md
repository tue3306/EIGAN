# examples/ — Exemplos e laboratório local

Arquivos para você ver valor **sem tocar em produção**. Só escaneie alvos que
você controla — o guardrail de escopo bloqueia o resto por padrão.

## Arquivos

- **`targets.example.txt`** — lista de alvos (um por linha) para o fluxo
  `vulnforge scan --target-list`. Contém apenas alvos **locais/ilustrativos**.
- **`../scope.example.yaml`** (na raiz) — modelo de escopo autorizado. Copie para
  `scope.yaml` e edite com **apenas** os seus alvos:
  ```bash
  cp scope.example.yaml scope.yaml
  ```

## Laboratório local (recomendado)

Suba um alvo vulnerável local e escaneie com perspectiva `internal`:

```bash
# OWASP Juice Shop (exemplo) — alvo que você controla, na sua máquina
docker run --rm -d -p 3000:3000 bkimminich/juice-shop

vulnforge scan --target 127.0.0.1:3000 --perspective internal \
  --profile web-only --scope scope.yaml
vulnforge report --scan 1 --format pdf
```

DVWA e Juice Shop são alvos de treino conhecidos; use-os no **seu** ambiente.
Nunca aponte o VulnForge para sistemas de terceiros sem autorização escrita.
