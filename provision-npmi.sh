#!/usr/bin/env bash
# provision-npmi — admin one-time provisioning of the npmi wrapper.
# Run as root/sudo on each developer workstation, VDI image, or remote desktop.
#
#   sudo ./provision-npmi.sh                 # installs wrapper only
#   sudo ./provision-npmi.sh alice bob       # also seed corp CA into user homes
#
# After this, developers simply run:  npmi   (or: npmi install)
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
DST=/usr/local/bin/npmi

command -v npm >/dev/null 2>&1 || echo "[!] npm not on PATH yet — install Node.js before handing this box to a developer"

install -m 0755 "$SRC/npmi.sh" "$DST"
echo "[+] npmi -> $DST (0755, world-executable)"

# Optional: distribute the corporate CA so npmi attaches it per-user at runtime
# (npmi reads ~/corp-ca.pem; profile only if that user lacks it)
if [ -f "$SRC/corp-ca.pem" ]; then
  for u in "$@"; do
    home=$(getent passwd "$u" | cut -d: -f6 || true)
    if [ -n "${home:-}" ] && [ -d "$home" ] && [ ! -f "$home/corp-ca.pem" ]; then
      install -o "$u" -g "$(id -gn "$u")" -m 0644 "$SRC/corp-ca.pem" "$home/corp-ca.pem"
      echo "[+] corp-ca.pem -> $home/ (user $u)"
    fi
  done
else
  echo "[*] no corp-ca.pem alongside this script — skipped CA seeding"
fi

# Smoke check (PATH only — do not execute, npmi would start an install)
if command -v npmi >/dev/null 2>&1; then
  echo "[+] npmi on PATH: $(command -v npmi)"
else
  echo "[!] npmi not on PATH — check /usr/local/bin is in the developer's PATH"
fi
echo "[+] done — developers run: npmi"
