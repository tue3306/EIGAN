#!/usr/bin/env bash
# Instalador idempotente do EIGAN. Detecta a distro e instala dependências
# de sistema do WeasyPrint + o pacote Python. NÃO instala as ferramentas de scan
# externas automaticamente (nmap/nuclei/...) — use Docker (recomendado) ou
# instale-as conforme config/tools.yaml (versões marcadas VERIFICAR).
set -euo pipefail

echo "EIGAN installer — uso autorizado apenas."

detect_distro() {
  if [ -f /etc/os-release ]; then . /etc/os-release; echo "${ID:-unknown}"; else echo "unknown"; fi
}

DISTRO="$(detect_distro)"
echo "Distro detectada: ${DISTRO}"

case "${DISTRO}" in
  debian|ubuntu|kali)
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip python3-venv \
      libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev
    ;;
  fedora)
    sudo dnf install -y python3 python3-pip pango gdk-pixbuf2 libffi-devel
    ;;
  arch)
    sudo pacman -S --needed --noconfirm python python-pip pango gdk-pixbuf2 libffi
    ;;
  *)
    echo "Distro não reconhecida; instale manualmente Python 3.11+ e libs do Pango."
    ;;
esac

python3 -m pip install --upgrade pip
python3 -m pip install -e ".[pdf,tui]"

cat <<'DONE'

────────────────────────────────────────────────────────────────────────────
✔ EIGAN instalado.

EIGAN é um AGENTE DE IA: nenhum scan roda sem um provedor de IA (§AI-native).
Próximos passos (fácil):

  1) eigan                       # abre o menu → Configuração → cole sua chave de IA
                                 #   (Claude, GPT, Gemini, Groq, Together, Azure ou Ollama local)
  2) eigan                       # menu → Novo Scan → informe o alvo → autorize → acompanhe
  3) veja o resultado:           # eigan serve  (dashboard em http://127.0.0.1:8000)
                                 #   ou gere o PDF/relatório ao final do scan

Power-user (headless):
  export EIGAN_AI_PROVIDER=anthropic ANTHROPIC_API_KEY=...   # ou outro provedor
  eigan plan empresa.com --goal attack-surface --execute --yes

Lembre: só escaneie o que você tem autorização para testar (scope.example.yaml → scope.yaml).
Guia de provedores de IA: docs/ai-providers.md
────────────────────────────────────────────────────────────────────────────
DONE
