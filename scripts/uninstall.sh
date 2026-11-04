#!/bin/bash
# Remove Homelab-Drift. Run as root.
#   sudo ./scripts/uninstall.sh            remove program, units, nginx site and gate; data and configuration stay
#   sudo ./scripts/uninstall.sh --purge    also delete /var/lib/homelab-drift, /etc/homelab-drift, logs and the user
# Remove the Prometheus scrape job and the Home Assistant automation by hand if needed (see README).
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Please run as root (sudo)."; exit 1; }
systemctl disable --now homelab-drift.timer homelab-drift-digest.timer 2>/dev/null || true
rm -f /etc/systemd/system/homelab-drift*.service /etc/systemd/system/homelab-drift*.timer
rm -rf /etc/systemd/system/homelab-drift.timer.d /etc/systemd/system/homelab-drift-digest.timer.d
systemctl daemon-reload
if [[ -L /etc/nginx/sites-enabled/homelab-drift ]]; then
  rm -f /etc/nginx/sites-enabled/homelab-drift /etc/nginx/sites-available/homelab-drift
  nginx -t && systemctl reload nginx
fi
rm -f /etc/logrotate.d/homelab-drift /usr/local/bin/homelab-drift
"$(dirname "$0")/install-host.sh" --remove || true
rm -rf /opt/homelab-drift
if [[ "${1-}" == "--purge" ]]; then
  rm -rf /var/lib/homelab-drift /etc/homelab-drift /var/log/homelab-drift
  userdel homelab-drift 2>/dev/null || true
fi
echo "Homelab-Drift removed."
