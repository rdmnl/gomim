#!/usr/bin/env bash
set -euo pipefail
CA="${1:-$HOME/.gomim/ca.pem}"
if [[ ! -f "$CA" ]]; then
  echo "CA not found: $CA (run gomim once to generate it)" >&2
  exit 1
fi
echo "Installing $CA into login keychain (you'll be prompted for your password)..."
security add-trusted-cert -d -r trustRoot -k "$HOME/Library/Keychains/login.keychain-db" "$CA"
echo "Done. Run with:"
echo "  HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080 <your command>"


# security delete-certificate -c "gomim Root CA" ~/Library/Keychains/login.keychain-db