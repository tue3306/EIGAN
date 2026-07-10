"""Detecção de suporte a PDF (WeasyPrint) — compartilhada por `doctor` e launcher.

O PDF é **opcional** (§12): HTML sempre funciona. O WeasyPrint carrega ligações
nativas (Pango / GDK-Pixbuf / libffi) já no `import`; se as libs de sistema
faltarem, o import falha (OSError). Esta checagem **degrada com clareza** e nunca
levanta — o produto continua, só o PDF vira HTML até as libs existirem.
"""

from __future__ import annotations

import importlib.util

_APT_LIBS = "libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev"


def pdf_status() -> tuple[bool, str]:
    """Retorna ``(disponível, detalhe)``. Distingue "não instalado" de "instalado
    mas sem as libs nativas de sistema". Nunca levanta."""
    if importlib.util.find_spec("weasyprint") is None:
        return False, "WeasyPrint não instalado — habilite com: pip install 'vulnforge[pdf]'."
    try:
        import weasyprint  # noqa: F401 — o import valida as libs nativas de sistema
    except Exception as exc:  # noqa: BLE001 — libs ausentes: OSError/OSError-like
        return False, (
            f"WeasyPrint instalado, mas faltam libs de sistema ({exc}). "
            f"No Debian/Ubuntu/Kali: sudo apt install {_APT_LIBS} — ou rode ./install.sh. "
            "Enquanto isso, o relatório sai em HTML."
        )
    return True, "WeasyPrint disponível — PDF habilitado."
