#!/usr/bin/env bash
# Instalador idempotente do VulnForge. Detecta a distro e instala dependências
# de sistema do WeasyPrint + o pacote Python. NÃO instala as ferramentas de scan
# externas automaticamente (nmap/nuclei/...) — use Docker (recomendado) ou
# instale-as conforme config/tools.yaml (versões marcadas VERIFICAR).
set -euo pipefail

echo "VulnForge installer — uso autorizado apenas."

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
python3 -m pip install -e ".[pdf]"

echo "OK. Rode:  vulnforge --help"
echo "Lembre: copie scope.example.yaml para scope.yaml e declare apenas alvos autorizados."
