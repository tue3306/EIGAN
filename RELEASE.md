# Processo de Release — EIGAN

Este documento descreve como uma versão do EIGAN é preparada e publicada.
Versionamento: [SemVer](https://semver.org/lang/pt-BR/). Changelog:
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) em [CHANGELOG.md](CHANGELOG.md).

## Checklist de release

1. **Verde local e na CI:** `ruff check`, `ruff format --check`, `mypy src`,
   `pytest` (ver `.github/workflows/ci.yml`).
2. **Instalação limpa** (`smoke-install`): `pip install .` → `eigan --version`,
   `eigan doctor`, `eigan plan … --dry-run` sem erro.
3. **Versão sincronizada:** `pyproject.toml` (`version`) e
   `src/eigan/__init__.py` (`__version__`) — fonte única, sem drift.
4. **CHANGELOG** atualizado com a seção da versão (data + Added/Changed/Fixed).
5. **Docs** refletem o estado real (README, `docs/`, ADRs).
6. **Tag anotada** `vX.Y.Z` e push:
   ```bash
   git tag -a vX.Y.Z -m "EIGAN vX.Y.Z — <resumo>"
   git push origin main --follow-tags
   ```
7. **GitHub Release** a partir da tag (notas = seção do CHANGELOG).
8. **PyPI** (quando o *trusted publisher* estiver configurado pelo dono):
   `.github/workflows/publish.yml` dispara no GitHub Release (OIDC, sem segredo
   no repo). Ver `docs/BLOCKERS.md` #5.

## Estado atual — `0.0.0` (pré-alfa, sem release publicado)

O versionamento foi **reiniciado para `0.0.0`** e as tags/releases `1.x`
anteriores foram removidas: elas superestimavam a maturidade (Blue era só
scaffold, não havia Purple real, o dashboard precisava de trabalho). Não há
release publicado — o número só volta a subir quando **Red, Blue e Purple**
rodarem de ponta a ponta com dashboard e relatórios à altura. Honestidade acima
de número de versão (§3.1). O histórico anterior está preservado no git.
