#!/usr/bin/env bash
set -euo pipefail
CA="${1:-$HOME/.gomim/ca.pem}"
if [[ ! -f "$CA" ]]; then
  echo "CA not found: $CA (run gomim once to generate it)" >&2
  exit 1
fi

if [[ -d /usr/local/share/ca-certificates ]] && command -v update-ca-certificates >/dev/null 2>&1; then
  # Debian / Ubuntu / Alpine
  DEST=/usr/local/share/ca-certificates/gomim.crt
  echo "Installing $CA -> $DEST (Debian/Ubuntu trust store)"
  sudo cp "$CA" "$DEST"
  sudo update-ca-certificates
elif [[ -d /etc/pki/ca-trust/source/anchors ]] && command -v update-ca-trust >/dev/null 2>&1; then
  # Fedora / RHEL / CentOS / Arch
  DEST=/etc/pki/ca-trust/source/anchors/gomim.crt
  echo "Installing $CA -> $DEST (Fedora/RHEL/Arch trust store)"
  sudo cp "$CA" "$DEST"
  sudo update-ca-trust
else
  echo "Could not detect a supported Linux trust store." >&2
  echo "Manually copy $CA into your distro's CA anchors directory and refresh trust." >&2
  exit 1
fi

echo "Done. Run with:"
echo "  HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080 <your command>"
echo
echo "Note: Node, Python, and other runtimes ignore the system trust store. You may also need:"
echo "  NODE_EXTRA_CA_CERTS=$CA      # Node"
echo "  SSL_CERT_FILE=$CA            # Python / Go"

# Uninstall:
#   Debian/Ubuntu:  sudo rm /usr/local/share/ca-certificates/gomim.crt && sudo update-ca-certificates --fresh
#   Fedora/RHEL:    sudo rm /etc/pki/ca-trust/source/anchors/gomim.crt && sudo update-ca-trust
