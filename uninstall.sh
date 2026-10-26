#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo ./uninstall.sh [--purge]" >&2
  exit 1
fi

PURGE=false
if [[ "${1:-}" == "--purge" || "${1:-}" == "-f" ]]; then
  PURGE=true
fi

echo "Stopping and disabling server-ai-agent service..."
systemctl disable --now server-ai-agent 2>/dev/null || true

echo "Removing systemd service and logrotate..."
rm -f /etc/systemd/system/server-ai-agent.service
rm -f /etc/logrotate.d/server-ai-agent
systemctl daemon-reload

echo "Removing application and configuration..."
rm -rf /opt/server-ai-agent
rm -rf /etc/server-ai-agent

if [[ "$PURGE" == true ]]; then
  echo "Purging state and log directories..."
  rm -rf /var/lib/server-ai-agent
  rm -rf /var/log/server-ai-agent
  if id server-agent >/dev/null 2>&1; then
    userdel server-agent 2>/dev/null || true
  fi
  echo "Complete uninstall (purged)."
else
  echo "Application and configuration removed."
  echo "Operational state and logs preserved:"
  echo "  /var/lib/server-ai-agent"
  echo "  /var/log/server-ai-agent"
  echo "Use 'sudo ./uninstall.sh --purge' to also delete state, logs, and service account."
fi
