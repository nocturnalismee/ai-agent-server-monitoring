#!/usr/bin/env bash
set -euo pipefail

APP_NAME=server-ai-agent
APP_DIR=/opt/server-ai-agent
ETC_DIR=/etc/server-ai-agent
STATE_DIR=/var/lib/server-ai-agent
LOG_DIR=/var/log/server-ai-agent
SERVICE_USER=server-agent

die() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "INFO: $*"; }

require_root() {
  [[ ${EUID} -eq 0 ]] || die "Run this installer as root: sudo ./install.sh"
}

load_os_release() {
  [[ -r /etc/os-release ]] || die "Cannot identify this operating system: /etc/os-release is missing."
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID=${ID:-unknown}
  OS_LIKE=${ID_LIKE:-}
}

is_rhel_family() {
  [[ " $OS_ID $OS_LIKE " == *" rhel "* || " $OS_ID $OS_LIKE " == *" fedora "* || " $OS_ID $OS_LIKE " == *" cloudlinux "* ]]
}

is_debian_family() {
  [[ " $OS_ID $OS_LIKE " == *" debian "* || " $OS_ID $OS_LIKE " == *" ubuntu "* ]]
}

detect_profile() {
  if [[ -x /usr/local/cpanel/cpanel || -d /usr/local/cpanel ]]; then
    PLATFORM_PROFILE=cpanel
    WEB_ERROR_LOGS=/etc/apache2/logs/error_log,/var/log/nginx/error.log
    AUTH_LOG_PRIMARY=/var/log/secure
    AUTH_LOG_SECONDARY=/var/log/auth.log
    SERVICE_CANDIDATES=httpd,sshd
  elif [[ -d /usr/local/psa || -d /etc/psa ]]; then
    PLATFORM_PROFILE=plesk
    WEB_ERROR_LOGS=/var/log/sw-cp-server/error_log,/var/log/plesk/panel.log,/var/log/nginx/error.log,/var/log/httpd/error_log,/var/log/apache2/error.log
    AUTH_LOG_PRIMARY=/var/log/secure
    AUTH_LOG_SECONDARY=/var/log/auth.log
    SERVICE_CANDIDATES=sw-cp-server,nginx,httpd,apache2,sshd,ssh
  elif [[ -d /usr/local/CyberCP ]]; then
    PLATFORM_PROFILE=cyberpanel
    # Keep panel defaults outside /home: ProtectHome=true deliberately prevents
    # access to tenant home directories, including CyberPanel's optional copy.
    WEB_ERROR_LOGS=/usr/local/lsws/logs/error.log
    AUTH_LOG_PRIMARY=/var/log/secure
    AUTH_LOG_SECONDARY=/var/log/auth.log
    SERVICE_CANDIDATES=lsws,lscpd,sshd,ssh
  elif [[ -d /usr/local/directadmin ]]; then
    PLATFORM_PROFILE=directadmin
    WEB_ERROR_LOGS=/var/log/directadmin/error.log,/var/log/httpd/error_log,/var/log/nginx/error.log
    AUTH_LOG_PRIMARY=/var/log/secure
    AUTH_LOG_SECONDARY=/var/log/auth.log
    SERVICE_CANDIDATES=directadmin,httpd,nginx,sshd,ssh
  elif [[ -d /www/server/panel ]]; then
    PLATFORM_PROFILE=aapanel
    WEB_ERROR_LOGS=/www/server/nginx/logs/error.log,/www/server/apache/logs/error_log
    AUTH_LOG_PRIMARY=/var/log/secure
    AUTH_LOG_SECONDARY=/var/log/auth.log
    SERVICE_CANDIDATES=nginx,httpd,apache2,sshd,ssh
  elif is_rhel_family; then
    PLATFORM_PROFILE=rhel
    WEB_ERROR_LOGS=/var/log/httpd/error_log,/var/log/nginx/error.log
    AUTH_LOG_PRIMARY=/var/log/secure
    AUTH_LOG_SECONDARY=/var/log/auth.log
    SERVICE_CANDIDATES=httpd,sshd
  elif is_debian_family; then
    PLATFORM_PROFILE=debian
    WEB_ERROR_LOGS=/var/log/apache2/error.log,/var/log/nginx/error.log
    AUTH_LOG_PRIMARY=/var/log/auth.log
    AUTH_LOG_SECONDARY=/var/log/secure
    SERVICE_CANDIDATES=apache2,ssh
  else
    die "Unsupported operating system: ID=$OS_ID ID_LIKE=$OS_LIKE"
  fi

  # Panels run on both Debian and RHEL-family distributions; auth and kernel logging
  # are chosen from the OS rather than the panel brand.
  if is_debian_family; then
    AUTH_LOG_PRIMARY=/var/log/auth.log
    AUTH_LOG_SECONDARY=/var/log/secure
    KERNEL_LOG_PRIMARY=/var/log/kern.log
    KERNEL_LOG_SECONDARY=/var/log/syslog
  else
    AUTH_LOG_PRIMARY=/var/log/secure
    AUTH_LOG_SECONDARY=/var/log/auth.log
    KERNEL_LOG_PRIMARY=/var/log/messages
    KERNEL_LOG_SECONDARY=/var/log/dmesg
  fi
}

resolve_default_services() {
  local service
  local -a candidates=()
  local -a active_services=()
  IFS=',' read -r -a candidates <<< "$SERVICE_CANDIDATES"
  if command -v systemctl >/dev/null 2>&1; then
    for service in "${candidates[@]}"; do
      if systemctl is-active --quiet "$service" 2>/dev/null; then
        active_services+=("$service")
      fi
    done
  fi
  if [[ ${#active_services[@]} -gt 0 ]]; then
    DEFAULT_SERVICES=$(IFS=,; echo "${active_services[*]}")
  else
    DEFAULT_SERVICES=$SERVICE_CANDIDATES
  fi
}

install_python() {
  if is_debian_family; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip ca-certificates acl
  elif is_rhel_family; then
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y python3 python3-pip ca-certificates acl
    elif command -v yum >/dev/null 2>&1; then
      yum install -y python3 python3-pip ca-certificates acl
    else
      die "No supported package manager for this RHEL-family system."
    fi
  else
    die "No supported package manager for this operating system."
  fi
}

select_python() {
  local candidate version
  for candidate in python3.13 python3.12 python3.11 python3.10 python3.9 python3 /opt/alt/python39/bin/python3 /opt/alt/python310/bin/python3 /opt/alt/python311/bin/python3 /opt/alt/python312/bin/python3 /opt/alt/python313/bin/python3 /opt/alt/python39/bin/python3.9 /opt/alt/python310/bin/python3.10 /opt/alt/python311/bin/python3.11 /opt/alt/python312/bin/python3.12 /opt/alt/python313/bin/python3.13; do
    command -v "$candidate" >/dev/null 2>&1 || continue
    version=$($candidate -c 'import sys; print(".".join(map(str, sys.version_info[:2])))' 2>/dev/null || true)
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)'; then
      PYTHON_BIN=$(command -v "$candidate")
      return 0
    fi
    note "Ignoring $candidate (Python $version); Python 3.9+ is required."
  done
  return 1
}

set_env_value() {
  local key=$1 value=$2 file=$3
  if grep -q "^${key}=" "$file"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
}

write_platform_defaults() {
  local env_file=$1
  set_env_value SERVICES "$DEFAULT_SERVICES" "$env_file"
  set_env_value WEB_ERROR_LOGS "$WEB_ERROR_LOGS" "$env_file"
  set_env_value AUTH_LOG "$AUTH_LOG_PRIMARY" "$env_file"
  set_env_value AUTH_LOG_RHEL "$AUTH_LOG_SECONDARY" "$env_file"
  set_env_value KERNEL_LOG "$KERNEL_LOG_PRIMARY" "$env_file"
  set_env_value KERNEL_LOG_RHEL "$KERNEL_LOG_SECONDARY" "$env_file"
  set_env_value PLATFORM_PROFILE "$PLATFORM_PROFILE" "$env_file"
}

configure_log_groups() {
  SERVICE_GROUPS=()
  local group
  for group in adm systemd-journal; do
    if getent group "$group" >/dev/null; then
      usermod -a -G "$group" "$SERVICE_USER"
      SERVICE_GROUPS+=("$group")
    fi
  done
}

install_unit() {
  install -m 0644 systemd/server-ai-agent.service /etc/systemd/system/server-ai-agent.service
  if [[ ${#SERVICE_GROUPS[@]} -eq 0 ]]; then
    sed -i '/^SupplementaryGroups=/d' /etc/systemd/system/server-ai-agent.service
  else
    sed -i "s/^SupplementaryGroups=.*/SupplementaryGroups=${SERVICE_GROUPS[*]}/" /etc/systemd/system/server-ai-agent.service
  fi
}

check_log_access() {
  local path
  local -a paths=("$AUTH_LOG_PRIMARY" "$AUTH_LOG_SECONDARY" "$KERNEL_LOG_PRIMARY" "$KERNEL_LOG_SECONDARY")
  local -a web_paths=()
  IFS=',' read -r -a web_paths <<< "$WEB_ERROR_LOGS"
  paths+=("${web_paths[@]}")
  note "Read-access check (missing logs are normal when the service is not installed):"
  for path in "${paths[@]}"; do
    if [[ ! -e $path ]]; then
      echo "  SKIP  $path (not present)"
    elif runuser -u "$SERVICE_USER" -- test -r "$path"; then
      echo "  OK    $path"
    else
      echo "  WARN  $path is not readable by $SERVICE_USER"
    fi
  done
}

print_profile() {
  load_os_release
  detect_profile
  resolve_default_services
  printf 'profile=%s\nos_id=%s\nos_like=%s\nweb_error_logs=%s\nauth_log=%s\nkernel_log=%s\nservices=%s\n' \
    "$PLATFORM_PROFILE" "$OS_ID" "$OS_LIKE" "$WEB_ERROR_LOGS" "$AUTH_LOG_PRIMARY" "$KERNEL_LOG_PRIMARY" "$DEFAULT_SERVICES"
}

main() {
  if [[ ${1:-} == --print-platform ]]; then
    print_profile
    return 0
  fi
  [[ $# -eq 0 ]] || die "Usage: $0 [--print-platform]"
  require_root

  local script_dir
  script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
  cd "$script_dir"
  [[ -d server_agent && -f requirements.txt && -f .env.example ]] || die "Run from the project directory."

  load_os_release
  detect_profile
  resolve_default_services
  note "Detected platform profile: $PLATFORM_PROFILE (ID=$OS_ID)"
  if ! select_python; then
    note "Python 3.9+ was not found; installing the OS Python packages."
    install_python
    select_python || die "Python 3.9+ was not found. On CloudLinux 7, install an Alt-Python 3.9+ package first."
  fi
  note "Using $PYTHON_BIN ($($PYTHON_BIN --version 2>&1))"

  if ! getent group "$SERVICE_USER" >/dev/null 2>&1; then
    groupadd --system "$SERVICE_USER"
  fi
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --gid "$SERVICE_USER" --home "$STATE_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
  fi
  configure_log_groups

  install -d -m 0755 "$APP_DIR" "$ETC_DIR"
  install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$STATE_DIR" "$LOG_DIR"
  cp -a server_agent requirements.txt "$APP_DIR"/
  "$PYTHON_BIN" -m venv "$APP_DIR/venv"
  "$APP_DIR/venv/bin/pip" install --upgrade pip
  "$APP_DIR/venv/bin/pip" install --disable-pip-version-check --no-input -r "$APP_DIR/requirements.txt"
  "$APP_DIR/venv/bin/python" -c "import site, pathlib; pathlib.Path(site.getsitepackages()[0], 'server-ai-agent.pth').write_text('$APP_DIR\n')"

  if [[ ! -f $ETC_DIR/server-ai-agent.env ]]; then
    install -m 0600 .env.example "$ETC_DIR/server-ai-agent.env"
    write_platform_defaults "$ETC_DIR/server-ai-agent.env"
    note "Created $ETC_DIR/server-ai-agent.env with $PLATFORM_PROFILE defaults."
  else
    note "Keeping existing configuration: $ETC_DIR/server-ai-agent.env"
  fi

  chown -R root:root "$APP_DIR"
  chmod -R go-w "$APP_DIR"
  install_unit
  install -m 0644 logrotate/server-ai-agent /etc/logrotate.d/server-ai-agent
  systemctl daemon-reload
  systemctl enable server-ai-agent
  check_log_access

  echo
  echo "Installation complete. Edit: sudo nano $ETC_DIR/server-ai-agent.env"
  echo "Validate: sudo systemd-run --wait --pipe --collect -p WorkingDirectory=$APP_DIR -p User=$SERVICE_USER -p Group=$SERVICE_USER -p EnvironmentFile=$ETC_DIR/server-ai-agent.env $APP_DIR/venv/bin/python -m server_agent --check-config"
  echo "Test notification: sudo systemd-run --wait --pipe --collect -p WorkingDirectory=$APP_DIR -p User=$SERVICE_USER -p Group=$SERVICE_USER -p EnvironmentFile=$ETC_DIR/server-ai-agent.env $APP_DIR/venv/bin/python -m server_agent --test-notification"
  echo "If a required log is unreadable, grant only read access using the distro/cPanel log policy or a reviewed ACL; do not run the agent as root."
}

main "$@"
