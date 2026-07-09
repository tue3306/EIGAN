<!-- Obrigado por contribuir! Preencha o essencial; PRs pequenos e focados são revisados mais rápido. -->

## O que muda e por quê

<!-- Descreva o *porquê*, não só o *o quê*. Link para a Issue: Closes #___ -->

## Tipo

- [ ] `feat` — nova funcionalidade / plugin
- [ ] `fix` — correção de bug
- [ ] `docs` — documentação
- [ ] `refactor` / `perf` / `test` / `chore`

## Definition of Done

- [ ] `ruff format .` e `ruff check src plugins tests` limpos
- [ ] `mypy src` sem erros
- [ ] `pytest -q` verde (inclui teste novo cobrindo a mudança)
- [ ] Documentação do módulo/plugin atualizada
- [ ] `CHANGELOG.md` atualizado (seção *Unreleased*)
- [ ] Sem código morto, sem segredo commitado

## Inegociáveis (confirmo que o PR respeita)

- [ ] **Anti-invenção:** nenhum CVE/CVSS/EPSS/KEV/versão/licença fabricado (não
      verificado ⇒ `UNVERIFIED`)
- [ ] **Autorização:** guardrail de escopo / consent gate não removidos
- [ ] **IA:** não executa scanner nem descobre vuln; todo recurso de IA tem
      fallback determinístico
- [ ] **Segurança de código:** sem `shell=True`, sem concatenar comando, sem
      secret no repo; validação/sanitização presentes
- [ ] Módulo não implementado entra como **scaffold honesto**, não stub falso

## Como testar

<!-- Comando(s) exato(s) para o revisor validar. Use apenas alvos locais/autorizados. -->

```bash
```
