#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo ./uninstall.sh"
  exit 1
fi
systemctl disable --now server-ai-agent 2>/dev/null || true
rm -f /etc/systemd/system/server-ai-agent.service
rm -f /etc/logrotate.d/server-ai-agent
systemctl daemon-reload
echo "Service removed."
echo "Configuration/state were intentionally preserved:"
echo "  /etc/server-ai-agent"
echo "  /var/lib/server-ai-agent"
echo "  /var/log/server-ai-agent"
echo "Remove them manually only if you no longer need them."
