# AI Agent Server Monitoring

A read-only Linux health and security monitoring agent for Ubuntu/Debian,
AlmaLinux/RHEL, and CloudLinux, with panel-aware defaults for cPanel/EA4,
Plesk, aaPanel, CyberPanel, and DirectAdmin.
It monitors host health and selected logs, then sends alerts through **one**
chosen channel: SMTP email or Telegram. Optional Gemini enrichment uses the
official HTTPS REST API through Python's standard library; no `google-genai`
SDK is installed.

## What it does

- Monitors CPU, memory, disk, and 1-minute load per CPU.
- Checks selected systemd services.
- Reads new Nginx and Apache error-log entries.
- Detects SSH logins, root logins, and failed-login bursts.
- Detects Out-Of-Memory (OOM) killer process terminations and kernel crashes/panics.
- Enriches high-severity alerts with Gemini AI triage and built-in sliding-window rate limiting.
- Sends recovery alerts after a monitored health/service condition returns to normal.
- Limits log processing per cycle to avoid unbounded memory use during log spikes.
- Stores cursors, alert cooldowns, and SSH counters locally and atomically.
- Runs as an unprivileged `server-agent` system account.

## What it does not do

The agent does not block IPs, restart services, alter firewall rules, execute
AI-provided commands, or modify application/server configuration. Its only
writes are its own application, state, log, systemd, and logrotate files during
installation or upgrade.

## Before installation

Run the installer only on a server you administer. It installs OS packages,
creates a system account, writes a systemd unit, and enables the service. It
requires:

- A supported OS with `systemd`: Ubuntu/Debian, AlmaLinux/RHEL, or CloudLinux.
- Internet access to GitHub, OS package repositories, and—only if enabled—the
  configured SMTP, Telegram, and Gemini endpoints.
- Python 3.9 or newer. On older CloudLinux systems, install an appropriate
  Alt-Python first; the installer checks common `/opt/alt/python*/bin/python3`
  locations.
- `git` installed on the server to use the GitHub deployment path below.

Never put real tokens, passwords, or API keys into Git. The project template
contains empty credential fields only.

## 1. Clone from GitHub

Connect to the target server with your normal administrative account, then
clone the reviewed branch into a temporary directory:

```bash
git clone --depth 1 --branch main \
  https://github.com/nocturnalismee/ai-agent-server-monitoring.git \
  /tmp/ai-agent-server-monitoring
cd /tmp/ai-agent-server-monitoring
```

Confirm that the checkout is clean and inspect the revision before granting the
installer root access:

```bash
git status --short
git log -1 --oneline
bash -n install.sh
bash -n uninstall.sh
./install.sh --print-platform
```

`git status --short` should produce no output. The `--print-platform` command
does not change the server; it shows the log paths and systemd service names
the installer will select.

For a repeatable production rollout, replace `main` with a reviewed release
tag or commit SHA once releases are published. The installer copies the
application into `/opt/server-ai-agent`; the temporary clone may be removed
after installation succeeds.

## 2. Install

From the cloned project directory:

```bash
sudo ./install.sh
```

The installer:

- installs Python, venv/pip, CA certificates, and ACL tooling through the OS package manager;
- creates the non-login `server-agent` account and available read-only log groups;
- installs the application at `/opt/server-ai-agent`;
- creates `/etc/server-ai-agent/server-ai-agent.env` with mode `0600` only if it does not already exist;
- installs and enables `server-ai-agent.service` and logrotate;
- reports whether the service account can read discovered SSH, Apache, and Nginx log files.

It does not start the service automatically. Configure and validate it first.

### Platform defaults

| Platform | Explicit web/panel error logs | Default service checks |
| --- | --- | --- |
| Ubuntu/Debian | Apache and Nginx global error logs | Active `apache2`/`ssh` services |
| AlmaLinux/RHEL | Apache and Nginx global error logs | Active `httpd`/`sshd` services |
| cPanel/EA4 | `/etc/apache2/logs/error_log`, optional Nginx log | Active `httpd`, `sshd` |
| Plesk | `sw-cp-server`, Plesk panel, Nginx, Apache global logs | Active Plesk/web/SSH services |
| aaPanel | aaPanel Nginx and Apache global logs | Active web/SSH services |
| CyberPanel | LiteSpeed global error log | Active `lsws`, `lscpd`, SSH services |
| DirectAdmin | DirectAdmin, Apache, and Nginx global logs | Active DirectAdmin/web/SSH services |

The installer detects cPanel, Plesk, aaPanel, CyberPanel, and DirectAdmin from
their local installation directories rather than from the OS name. It selects
only currently active candidate services on a new install; if none can be
determined, it writes conservative panel defaults. On later installs it
preserves the existing environment file, so review paths and service names when
the host configuration changes.

For tenant isolation the service uses `ProtectHome=true`, so it intentionally
does not monitor optional panel log copies under `/home`. On CyberPanel, the
default is LiteSpeed's global error log at `/usr/local/lsws/logs/error.log`.

## 3. Configure alerts

Edit the protected configuration file:

```bash
sudo nano /etc/server-ai-agent/server-ai-agent.env
```

Set `SERVER_NAME` and choose exactly one delivery channel. Leave unused
channel credentials empty.

### SMTP email

```dotenv
SERVER_NAME=prod-web-01
ENVIRONMENT=production

ALERT_CHANNEL=email
SMTP_HOST=email-smtp.ap-south-1.amazonaws.com
SMTP_PORT=587
SMTP_SECURITY=starttls
SMTP_USERNAME=YOUR_SES_SMTP_USERNAME
SMTP_PASSWORD=YOUR_SES_SMTP_PASSWORD
SMTP_FROM=verified-sender@example.com
SMTP_TO=ops@example.com,oncall@example.com
```

Amazon SES SMTP credentials are different from AWS access keys. Use `starttls`
or `ssl`; unencrypted SMTP is not accepted.

### Telegram

```dotenv
SERVER_NAME=prod-web-01
ENVIRONMENT=production

ALERT_CHANNEL=telegram
TELEGRAM_BOT_TOKEN=123456789:REPLACE_WITH_BOT_TOKEN
TELEGRAM_CHAT_ID=-1001234567890
# Empty for a private chat or normal group. Set only for a forum topic.
TELEGRAM_MESSAGE_THREAD_ID=
```

The bot must be a member of the target chat and permitted to post. A group or
supergroup chat ID is often negative. `TELEGRAM_MESSAGE_THREAD_ID` is optional
and only applies to forum-enabled supergroups.

### Optional Gemini AI enrichment

```dotenv
GEMINI_ENABLED=true
GEMINI_API_KEY=YOUR_GEMINI_API_KEY
GEMINI_MODEL=gemini-2.5-flash
GEMINI_TIMEOUT_SECONDS=8
GEMINI_MAX_OUTPUT_TOKENS=400
GEMINI_RATE_LIMIT_PER_MINUTE=10
```

No additional Python package is required: Gemini is called with HTTPS REST via
the Python standard library. AI is enrichment only; alert delivery continues
when Gemini is disabled, rate-limited, or unavailable. A 60-second sliding window
rate limiter (`GEMINI_RATE_LIMIT_PER_MINUTE`) prevents quota exhaustion during
alert storms.

Before telemetry leaves the server for Gemini, Telegram, or email, the agent
redacts common credentials: API keys, tokens, passwords, authorization/cookie
headers, sensitive URL parameters, database URI passwords, and private keys.
The original monitored files are never modified. Review initial alerts because
pattern-based redaction cannot identify every custom secret format.

### Panel-specific web logs

`WEB_ERROR_LOGS` is a comma-separated list of explicit absolute paths. The
installer fills it for a newly detected panel. This agent intentionally does
not recursively discover every domain/vhost log: scanning `/var/www`, `/home`,
or `/www/wwwlogs` on a shared-hosting server would create unpredictable I/O and
could expose tenant data. Add a small, reviewed list of specific high-value
logs if required:

```dotenv
WEB_ERROR_LOGS=/var/log/directadmin/error.log,/var/log/httpd/error_log
```

### Kernel and OOM monitoring

The agent inspects `/var/log/kern.log` (Debian/Ubuntu) or `/var/log/messages` (RHEL/CentOS)
for Out-Of-Memory (OOM) killer events and kernel crashes. On minimal systemd installations
where traditional log files are absent, it automatically falls back to `journalctl -k`
using atomic state cursors.

```dotenv
KERNEL_MONITOR_ENABLED=true
KERNEL_LOG=/var/log/kern.log
KERNEL_LOG_RHEL=/var/log/messages
KERNEL_JOURNAL_FALLBACK=true
```

## 4. Confirm log access

The installer prints a read-access report. Recheck the files actually used by
your platform as the service account:

```bash
sudo -u server-agent test -r /var/log/auth.log && echo auth-readable
sudo -u server-agent test -r /var/log/secure && echo secure-readable
sudo -u server-agent test -r /var/log/nginx/error.log && echo nginx-readable
sudo -u server-agent test -r /var/log/apache2/error.log && echo apache-readable
sudo -u server-agent test -r /var/log/httpd/error_log && echo httpd-readable
sudo -u server-agent test -r /etc/apache2/logs/error_log && echo cpanel-apache-readable
```

Missing files are normal when the corresponding service is not installed. If a
required existing log is unreadable, grant only read access through the host's
group/ACL policy—never run the agent as root. For example:

```bash
sudo setfacl -m u:server-agent:r /var/log/secure
```

On cPanel, review Apache log ownership and mode after EasyApache or cPanel
updates. The installer only reports permission problems; it never changes
cPanel/Apache log permissions automatically.

## 5. Validate and test

Validate the configuration in a transient unit with the same account and
environment file as the service:

```bash
sudo systemd-run --wait --pipe --collect \
  -p WorkingDirectory=/opt/server-ai-agent \
  -p User=server-agent -p Group=server-agent \
  -p EnvironmentFile=/etc/server-ai-agent/server-ai-agent.env \
  /opt/server-ai-agent/venv/bin/python -m server_agent --check-config
```

Expected output:

```text
Configuration OK
```

Validate the installed unit and logrotate policy without starting or rotating
anything:

```bash
sudo systemd-analyze verify /etc/systemd/system/server-ai-agent.service
sudo logrotate -d /etc/logrotate.d/server-ai-agent
```

Send one test message through the selected Email or Telegram channel:

```bash
sudo systemd-run --wait --pipe --collect \
  -p WorkingDirectory=/opt/server-ai-agent \
  -p User=server-agent -p Group=server-agent \
  -p EnvironmentFile=/etc/server-ai-agent/server-ai-agent.env \
  /opt/server-ai-agent/venv/bin/python -m server_agent --test-notification
```

## 6. Start and observe

```bash
sudo systemctl start server-ai-agent
sudo systemctl status server-ai-agent --no-pager
sudo journalctl -u server-ai-agent -f
```

Application log:

```bash
sudo tail -f /var/log/server-ai-agent/agent.log
```

On first observation of a log file, the agent starts at EOF. This prevents
historical entries from generating a flood of alerts after installation.

## Configuration reference

Key operational settings from the generated environment file:

| Setting | Default | Purpose |
| --- | ---: | --- |
| `HEALTH_INTERVAL` | `60` | Health/service collection interval in seconds. |
| `LOG_INTERVAL` | `15` | Log polling interval in seconds. |
| `MAX_LOG_LINES_PER_CYCLE` | `250` | Maximum lines read from each file per log cycle. |
| `MAX_LOG_LINE_CHARS` | `4096` | Maximum retained characters from one physical log line; oversized lines are consumed and truncated. |
| `ALERT_COOLDOWN_SECONDS` | `900` | Suppresses repeated alerts for the same fingerprint. |
| `RECOVERY_ALERTS` | `true` | Sends a recovery event after a health/service condition clears. |
| `SSH_FAILED_THRESHOLD` | `5` | Failed logins from one IP before an SSH burst alert. |
| `SSH_FAILED_WINDOW_SECONDS` | `300` | Time window for failed SSH-login counting. |
| `WEB_ERROR_BATCH_THRESHOLD` | `1` | Matching web-log entries required before an alert. |
| `MAX_LOG_SAMPLE_CHARS` | `600` | Maximum retained characters per outbound log sample. |
| `SSH_FAILURE_TRACKED_IPS_MAX` | `1000` | Maximum source IPs retained for SSH burst tracking. |

`SERVICES`, log paths, disk paths, thresholds, trusted SSH networks, and the
alert channel are all configurable in `/etc/server-ai-agent/server-ai-agent.env`.
The configuration validator rejects invalid channel, TLS, numeric, and
threshold settings before the service starts. It also rejects relative
`WEB_ERROR_LOGS` paths and more than 12 monitored web/panel logs.

## Safe operational tests

For a controlled health-alert test, temporarily set a low threshold, restart,
confirm the alert, then restore the normal value:

```dotenv
CPU_WARNING=1
```

```bash
sudo systemctl restart server-ai-agent
```

Use an existing harmless test environment for Nginx/Apache log testing; do not
intentionally break production services. A successful SSH login generates an
alert when `SSH_ALERT_SUCCESS=true`.

## Upgrade from GitHub

The safest update method is a fresh clone and a controlled restart. It keeps
the existing protected configuration, state, and application logs.

```bash
sudo systemctl stop server-ai-agent
workdir=$(mktemp -d /tmp/ai-agent-server-monitoring-update.XXXXXX)
git clone --depth 1 --branch main \
  https://github.com/nocturnalismee/ai-agent-server-monitoring.git \
  "$workdir"
cd "$workdir"
git log -1 --oneline
bash -n install.sh
sudo ./install.sh
```

Then rerun the validation and test-notification commands above before starting
the service again. For critical systems, use a reviewed release tag or commit
SHA instead of `main`, and preserve a copy of the prior `/opt/server-ai-agent`
directory before upgrade.

## Operations

```bash
# Restart after a configuration change
sudo systemctl restart server-ai-agent

# Recent service logs
sudo journalctl -u server-ai-agent --since "1 hour ago"

# Disable without uninstalling
sudo systemctl disable --now server-ai-agent

# Remove the systemd and logrotate files; config, state, and logs remain
sudo ./uninstall.sh
```

Installed locations:

```text
/opt/server-ai-agent                       Application and virtual environment
/etc/server-ai-agent/server-ai-agent.env   Protected configuration and secrets
/var/lib/server-ai-agent                   State, cursors, and cooldown records
/var/log/server-ai-agent/agent.log         Application log
```

The service is deliberately low impact: health collection is periodic,
CPU measurement is non-blocking, service checks use one short `systemctl`
query per configured service, web logs are read incrementally in bounded
batches, SSH failure state is capped, and the systemd unit runs with lower CPU
and I/O priority than normal hosted workloads.

## Developer checks

On a development host with Python available, install development dependencies
in an isolated environment and run:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python3 -m pytest -q
```

The project includes tests for SSH parsing, Telegram payloads, Gemini REST
response parsing, and outbound secret redaction.
