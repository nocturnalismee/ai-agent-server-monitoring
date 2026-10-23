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
    APACHE_LOG=/etc/apache2/logs/error_log
    AUTH_LOG_PRIMARY=/var/log/secure
    AUTH_LOG_SECONDARY=/var/log/auth.log
    DEFAULT_SERVICES=httpd,sshd
  elif is_rhel_family; then
    PLATFORM_PROFILE=rhel
    APACHE_LOG=/var/log/httpd/error_log
    AUTH_LOG_PRIMARY=/var/log/secure
    AUTH_LOG_SECONDARY=/var/log/auth.log
    DEFAULT_SERVICES=httpd,sshd
  elif is_debian_family; then
    PLATFORM_PROFILE=debian
    APACHE_LOG=/var/log/apache2/error.log
    AUTH_LOG_PRIMARY=/var/log/auth.log
    AUTH_LOG_SECONDARY=/var/log/secure
    DEFAULT_SERVICES=apache2,ssh
  else
    die "Unsupported operating system: ID=$OS_ID ID_LIKE=$OS_LIKE"
  fi
}

install_python() {
  if is_debian_family; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip ca-certificates acl
  elif is_rhel_family; then
    dnf install -y python3 python3-pip ca-certificates acl
  else
    die "No supported package manager for this operating system."
  fi
}

select_python() {
  local candidate version
  for candidate in python3.13 python3.12 python3.11 python3.10 python3.9 python3 /opt/alt/python39/bin/python3 /opt/alt/python310/bin/python3 /opt/alt/python311/bin/python3 /opt/alt/python39/bin/python3.9 /opt/alt/python310/bin/python3.10 /opt/alt/python311/bin/python3.11; do
    command -v "$candidate" >/dev/null 2>&1 || continue
    version=$($candidate -c 'import sys; print(".".join(map(str, sys.version_info[:2])))' 2>/dev/null || true)
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)'; then
      PYTHON_BIN=$(command -v "$candidate")
      return 0
    fi
    note "Ignoring $candidate (Python $version); Python 3.9+ is required."
  done
  die "Python 3.9+ was not found. On CloudLinux 7, install an alt-Python 3.9+ package first."
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
  set_env_value APACHE_ERROR_LOG "$APACHE_LOG" "$env_file"
  set_env_value APACHE_RHEL_ERROR_LOG "$APACHE_LOG" "$env_file"
  set_env_value AUTH_LOG "$AUTH_LOG_PRIMARY" "$env_file"
  set_env_value AUTH_LOG_RHEL "$AUTH_LOG_SECONDARY" "$env_file"
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
  local -a paths=("$AUTH_LOG_PRIMARY" "$APACHE_LOG" /var/log/nginx/error.log)
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
  printf 'profile=%s\nos_id=%s\nos_like=%s\napache_log=%s\nauth_log=%s\nservices=%s\n' \
    "$PLATFORM_PROFILE" "$OS_ID" "$OS_LIKE" "$APACHE_LOG" "$AUTH_LOG_PRIMARY" "$DEFAULT_SERVICES"
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
  note "Detected platform profile: $PLATFORM_PROFILE (ID=$OS_ID)"
  install_python
  select_python
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
  echo "Validate: sudo systemd-run --wait --pipe --collect -p User=$SERVICE_USER -p Group=$SERVICE_USER -p EnvironmentFile=$ETC_DIR/server-ai-agent.env $APP_DIR/venv/bin/python -m server_agent --check-config"
  echo "Test notification: sudo systemd-run --wait --pipe --collect -p User=$SERVICE_USER -p Group=$SERVICE_USER -p EnvironmentFile=$ETC_DIR/server-ai-agent.env $APP_DIR/venv/bin/python -m server_agent --test-notification"
  echo "If a required log is unreadable, grant only read access using the distro/cPanel log policy or a reviewed ACL; do not run the agent as root."
}

main "$@"
