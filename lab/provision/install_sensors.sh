#!/usr/bin/env bash
# Install osquery + Falco on a Linux victim host (Ubuntu 22.04/24.04, Debian 12+).
# Run as root: sudo bash install_sensors.sh
# Idempotent: safe to re-run.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "run as root: sudo bash $0" >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "[1/4] osquery apt repo + install"
mkdir -p /etc/apt/keyrings
curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg -o /etc/apt/keyrings/osquery.asc
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/osquery.asc] https://pkg.osquery.io/deb deb main" \
    > /etc/apt/sources.list.d/osquery.list

echo "[2/4] Falco apt repo + install"
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
    | gpg --dearmor --yes -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" \
    > /etc/apt/sources.list.d/falcosecurity.list

apt-get update
# FALCO_FRONTEND=noninteractive skips the interactive driver-selection dialog;
# we pick the modern eBPF driver explicitly via the systemd unit below.
FALCO_FRONTEND=noninteractive apt-get install -y osquery falco

echo "[3/4] apply configs"
install -m 0644 "$REPO_DIR/lab/provision/osquery.conf" /etc/osquery/osquery.conf
mkdir -p /etc/falco/config.d /etc/falco/rules.d /var/log/falco
install -m 0644 "$REPO_DIR/deploy/falco/falco_overrides.yaml" /etc/falco/config.d/99-edr.yaml
install -m 0644 "$REPO_DIR/deploy/falco/edr_rules.yaml" /etc/falco/rules.d/edr_rules.yaml

echo "[4/4] enable services"
systemctl enable --now osqueryd
# modern eBPF driver: no kernel module build, works on kernels >= 5.8
systemctl enable --now falco-modern-bpf.service

echo "done. verify with:"
echo "  sudo tail -f /var/log/falco/events.json"
echo "  sudo tail -f /var/log/osquery/osqueryd.results.log"
