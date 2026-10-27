# AI Agent Server Monitoring

A read-only, high-performance Linux health, security, and log monitoring agent for **Ubuntu/Debian**, **AlmaLinux/RHEL**, and **CloudLinux**, with built-in auto-discovery and context awareness for hosting control panels: **cPanel/WHM**, **aaPanel**, **CyberPanel**, **CloudPanel**, **Plesk**, **DirectAdmin**, **HestiaCP**, **VestaCP**, and **RunCloud**.

It monitors host health and selected logs, collects real-time diagnostic evidence (`journalctl` / top processes), and sends alerts through **one** chosen channel: **SMTP email** or **Telegram**. High-severity incidents are enriched with multi-provider AI triage (DeepSeek, OpenAI, Claude, Groq, Kimi, Gemini, or OpenRouter) using the official HTTPS REST API through Python's standard library—**no third-party AI SDKs are required**.

---

## What it does

- **Context-Aware AI Diagnosis**: Automatically identifies host OS (e.g. CloudLinux, Ubuntu, AlmaLinux) and hosting control panels (cPanel, aaPanel, CyberPanel, etc.). AI prompts are dynamically injected with specific CLI tools, configuration paths, and safe troubleshooting procedures tailored to that exact environment.
- **Dynamic Service Discovery**: Automatically detects which systemd services are actually installed on the server to eliminate false alerts for uninstalled services.
- **Pre-AI Incident Evidence Capture**: When a service crashes or CPU/RAM spikes, the agent captures the last 15 lines of `journalctl -u <service>` or top processes before calling AI, giving the AI real log proof for accurate root cause analysis.
- **Clean, One-Tap Copy Telegram Alerts**: Telegram notifications feature short server identifiers, environment badges (`🏷️ CloudLinux 8.5 · cPanel · LiteSpeed`), structured details, and copy-pasteable monospace commands.
- **Host Health Monitoring**: Non-blocking periodic checks for CPU, RAM, Disk mounts, and 1-minute load average per CPU.
- **Security & SSH Tracking**: Detects successful logins, unauthorized root logins, and distributed brute-force bursts with persistent IP tracking and cooldowns.
- **Kernel & OOM Monitoring**: Detects Out-Of-Memory (OOM) killer terminations and kernel panics via `/var/log/kern.log`, `/var/log/messages`, or `journalctl -k` fallback.
- **Web Server Error Logs**: Parses Apache, Nginx, and LiteSpeed global error logs in bounded batches to avoid unbounded memory use during traffic surges.
- **Local Credential Sanitization**: Passwords, API keys, bearer tokens, private keys, and connection strings are redacted locally before any telemetry leaves the server.
- **Zero Destructive Actions**: Runs under an unprivileged `server-agent` system account. It never executes commands or alters server configurations automatically.

---

## Architecture & Codebase Layout

The project follows a clean, enterprise modular architecture:

```text
server_agent/
├── core/                     # Foundational primitives
│   ├── config.py             # Environment configuration & strict validation
│   ├── models.py             # Incident & ServerMetadata dataclasses
│   ├── state.py              # File cursors, cooldowns, and SSH failure state
│   ├── logging_setup.py      # Structured rotating file & stream logger
│   └── redaction.py          # Data sanitizer (masks credentials, keys, tokens)
│
├── detectors/                # Auto-discovery engines
│   ├── environment.py        # OS (CloudLinux/Alma/Ubuntu), Panel (cPanel/aaPanel/etc), & Stack
│   └── services.py           # Filters out uninstalled services to avoid false alarms
│
├── collectors/               # Evidence & telemetry collectors
│   ├── evidence.py           # Real-time snapshot of journalctl / top CPU-RAM processes
│   └── filetail.py           # Incremental log file tailer with inode tracking
│
├── monitors/                 # Health & security monitors
│   ├── health.py             # CPU, RAM, Disk, Load, and dynamic service checker
│   ├── kernel.py             # Kernel panics, OOM killer process terminations
│   ├── ssh.py                # SSH logins and brute-force tracking
│   └── web.py                # Web server global error log parser
│
├── ai/                       # AI Intelligence & Prompt Engineering
│   ├── analyzer.py           # Multi-provider client (DeepSeek, OpenAI, Claude, Gemini, Groq)
│   └── prompts.py            # Dynamic system instruction builder customized per OS & Panel
│
├── notifiers/                # Notification transports
│   ├── base.py               # Abstract BaseNotifier
│   ├── telegram.py           # Telegram bot notifier with HTML formatting & badges
│   └── emailer.py            # SMTP email notifier
│
├── agent.py                  # Main Daemon loop & event dispatcher
└── __main__.py               # CLI entrypoint (--check-config, --test-notification, etc.)
```

---

## Prerequisites

- **Linux with systemd** (Ubuntu/Debian, AlmaLinux/RHEL, CloudLinux, or a supported hosting panel).
- **Python 3.9 or newer** (the installer sets up a virtual environment; `python3-venv` is installed if needed).
- **Root or sudo** access for installation and service management.
- **Read access** to the logs you want to monitor (`auth.log`/`secure`, web server error logs, kernel logs) and to the systemd journal.
- **Outbound network access** for Telegram (HTTPS) and/or your SMTP relay, plus your AI provider when AI enrichment is enabled.

---

## 1. Clone from GitHub

Connect to your target server and clone the repository:

```bash
git clone --depth 1 --branch main \
  https://github.com/nocturnalismee/ai-agent-server-monitoring.git \
  /tmp/ai-agent-server-monitoring
cd /tmp/ai-agent-server-monitoring
```

Inspect platform defaults detected by the installer:

```bash
./install.sh --print-platform
```

---

## 2. Install

Run the installer as root:

```bash
sudo ./install.sh
```

The installer:
- Installs Python 3, venv, and required OS packages (`apt`, `dnf`, or `yum`).
- Creates the non-login `server-agent` system user.
- Installs the application to `/opt/server-ai-agent`.
- Generates `/etc/server-ai-agent/server-ai-agent.env` with mode `0600` (preserves existing config on update).
- Configures the systemd service, the heartbeat watchdog service/timer, and logrotate.

The service is installed but left stopped until you configure it. After editing
the environment file, start the agent and enable the watchdog timer:

```bash
sudo systemctl start server-ai-agent
sudo systemctl enable --now server-ai-agent-watchdog.timer
```

---

## 3. Configuration

Edit the protected configuration file:

```bash
sudo nano /etc/server-ai-agent/server-ai-agent.env
```

### Server Identity & Auto-Discovery

```dotenv
# Leave SERVER_NAME unset to auto-detect system hostname
# SERVER_NAME=prod-web-01
ENVIRONMENT=production

# Auto-detect OS distro (CloudLinux, Alma, Ubuntu) & Control Panel (cPanel, aaPanel, CyberPanel, etc.)
AUTO_DETECT_ENVIRONMENT=true

# Filter a legacy SERVICES list to installed units (profiles handle panel detection)
AUTO_DETECT_SERVICES=true

# Capture real-time evidence (journalctl -u <service> or top CPU/RAM processes) when incidents occur
COLLECT_INCIDENT_EVIDENCE=true
EVIDENCE_LINES=15
```

### Telegram Notification (Recommended)

```dotenv
ALERT_CHANNEL=telegram
TELEGRAM_BOT_TOKEN=123456789:REPLACE_WITH_BOT_TOKEN
TELEGRAM_CHAT_ID=-1001234567890
# Optional: set only for a forum topic / supergroup thread
TELEGRAM_MESSAGE_THREAD_ID=
```

### Multi-Server Deployment (Telegram Topics)

When running the agent on many servers (VPS, dedicated, or WHM/cPanel shared
hosting), route every server into **one Telegram supergroup with Topics
enabled** and give each server its own topic. Each instance posts to its own
`TELEGRAM_MESSAGE_THREAD_ID`, so alerts stay separated per server. **This needs
no code changes** — only configuration.

**Setup**

1. Create a Telegram **supergroup** and enable **Topics** in the group settings.
2. Add your bot to the group. Grant it permission to post messages (making it an
   admin is the simplest reliable option).
3. Get the group `chat_id` (a negative id beginning with `-100`, e.g. via
   `https://api.telegram.org/bot<token>/getUpdates` after posting in the group).
4. Create one topic per server. Open the topic and read its `message_thread_id`
   from the topic link (`https://t.me/c/<internal_id>/<thread_id>`) or from the
   `message_thread_id` field in `getUpdates`.
5. Configure each server's `/etc/server-ai-agent/server-ai-agent.env` with the
   shared `TELEGRAM_CHAT_ID` and that server's own thread id.

**Per-server configuration template** (also available at
[`examples/multi-server.env.example`](examples/multi-server.env.example)):

```dotenv
# Required
ALERT_CHANNEL=telegram
TELEGRAM_BOT_TOKEN=123456789:REPLACE_WITH_BOT_TOKEN
TELEGRAM_CHAT_ID=-1001234567890

# Unique topic for THIS server
TELEGRAM_MESSAGE_THREAD_ID=42

# Unique, stable identity shown in every alert (hostname or logical name)
SERVER_NAME=whm-cust123
ENVIRONMENT=production
```

**Operational guidance**

- Keep `SERVER_NAME` unique and stable (e.g. `whm-cust123`, `vps-sg-01`). It is
  the primary way operators tell servers apart; OS/panel badges are auto-detected
  and shown alongside it.
- One bot token can serve the whole fleet. Use a separate bot only when a
  customer's Telegram access must be isolated.
- `ALERT_COOLDOWN_SECONDS` (default `900`) suppresses duplicate alerts per
  fingerprint, so repeated incidents do not flood a topic.
- `INFO`/`RECOVERY` alerts are delivered with `disable_notification`, so only
  `WARNING`/`CRITICAL` incidents make sound. Explicit test notifications always
  sound.
- Common layouts: one topic per server (recommended), one topic per customer
  bucket, or one group per customer (different `TELEGRAM_CHAT_ID` per server).
- For severity-based routing, set `ESCALATION_CHANNEL=telegram` with a central
  chat id; WARNING/CRITICAL incidents go to both the per-server channel and the
  central one (see Critical Alert Escalation below).

### Critical Alert Escalation

Keep per-server alerts in their own topics while still paging a central ops
channel for serious incidents. The primary channel always receives every alert;
the escalation channel receives only incidents at or above
`ESCALATION_MIN_SEVERITY`.

```env
ESCALATION_CHANNEL=telegram
ESCALATION_TELEGRAM_BOT_TOKEN=
ESCALATION_TELEGRAM_CHAT_ID=-1001234567890
ESCALATION_TELEGRAM_MESSAGE_THREAD_ID=
ESCALATION_MIN_SEVERITY=CRITICAL
```

Leave `ESCALATION_TELEGRAM_BOT_TOKEN` empty to reuse `TELEGRAM_BOT_TOKEN`. The
same per-fingerprint cooldown applies to both channels, so a CRITICAL alert is
not repeated every cycle. `--test-notification` sends a test to both the primary
and escalation destinations.

### Service Monitoring

The agent watches a per-panel set of systemd services. The default
`SERVICE_PROFILE=auto` follows the detected control panel and falls back to
`standalone` when no panel is recognized. `SERVICE_PROFILE=none` disables the
built-in lists; use it with explicit `SERVICES_REQUIRED`/`SERVICES_OPTIONAL`
overrides.

| Profile | Required (alert if missing/inactive) | Optional (alert if installed but inactive) |
| :--- | :--- | :--- |
| standalone | ssh | nginx, apache2, httpd, mysql, redis, docker |
| cpanel | cpanel, mysql, exim, dovecot | named, httpd, lsws, cphulkd, pure-ftpd, clamd, spamd, redis, php-fpm |
| cyberpanel | lscpd, lsws, mariadb | postfix, pure-ftpd, dovecot, powerdns, redis, php-fpm |
| aapanel | bt, mysql | nginx, httpd, apache2, php-fpm, redis, pure-ftpd, postgresql |
| plesk | sw-cp-server, sw-engine, psa | nginx, apache2, httpd, postfix, dovecot, mysql, redis, php-fpm |
| directadmin | directadmin | httpd, nginx, apache2, exim, dovecot, mysql, php-fpm, redis |
| hestiacp | hestia | nginx, apache2, exim, dovecot, mysql, named, vsftpd, php-fpm, redis |
| cloudpanel | clp-nginx, clp-php-fpm | mysql, redis |
| runcloud | nginx | php-fpm, mysql, redis |

`php-fpm` in a profile matches only the unversioned unit; versioned units such as
`php8.2-fpm` are not inferred. List them explicitly if you monitor them.

Override precedence (highest first):

1. `SERVICES` (legacy) — when non-empty, replaces both lists and keeps
   `AUTO_DETECT_SERVICES` filtering. It is empty by default.
2. `SERVICES_REQUIRED` — when non-empty, replaces the profile's required list.
3. `SERVICES_OPTIONAL` — when non-empty, replaces the profile's optional list.
4. `SERVICE_PROFILE` — supplies any list not overridden; `auto` follows the
   detected panel.

Common aliases are resolved automatically: `ssh`/`sshd`,
`apache2`/`httpd`/`apache`, `mysql`/`mariadb`/`mysqld`, `exim`/`exim4`,
`named`/`bind9`/`named-chroot`.

Severity and timing:

- A required service that is missing (`not-found`) alerts `CRITICAL`; a missing
  optional service is skipped.
- A required service whose state is unknown alerts `WARNING`; an optional
  service is skipped unless `ALERT_ON_MISSING_SERVICE=true`.
- A `failed` unit alerts immediately: `CRITICAL` when required, `WARNING` when
  optional.
- Other non-active states alert after `SERVICE_FAILURE_THRESHOLD` consecutive
  non-active checks (default `2`).
- Recovery notices are `INFO` when `RECOVERY_ALERTS=true`.

Incident evidence uses the resolved unit: read-only `journalctl -u <unit>` and
`systemctl status --no-pager -l -- <unit>`.

To print the effective service plan, run:

```bash
sudo -u server-agent /opt/server-ai-agent/venv/bin/python -m server_agent --check-config
```

After `Configuration OK`, the output shows the resolved profile (mode `auto` for
`SERVICE_PROFILE=auto`, otherwise `explicit`) and both lists:

```text
Configuration OK
Service profile: cpanel (auto)
Required: cpanel, mysql, exim, dovecot
Optional: named, httpd, lsws, cphulkd, pure-ftpd, clamd, spamd, redis, php-fpm
```

### SMTP Email

```dotenv
ALERT_CHANNEL=email
SMTP_HOST=email-smtp.ap-south-1.amazonaws.com
SMTP_PORT=587
SMTP_SECURITY=starttls
SMTP_USERNAME=YOUR_SMTP_USERNAME
SMTP_PASSWORD=YOUR_SMTP_PASSWORD
SMTP_FROM=alerts@example.com
SMTP_TO=ops@example.com,oncall@example.com
```

### Multi-Provider AI Enrichment

Supports multiple providers without installing third-party SDKs:

- **DeepSeek** (`AI_PROVIDER=deepseek`): Fast, low cost, excellent Linux SRE reasoning.
- **OpenAI** (`AI_PROVIDER=openai`): Supports `gpt-4o-mini`, `gpt-4o`.
- **Claude** (`AI_PROVIDER=claude`): Supports `claude-3-5-haiku-20241022`.
- **Groq** (`AI_PROVIDER=groq`): Fast inference (`llama-3.3-70b-versatile`).
- **Kimi / Moonshot** (`AI_PROVIDER=kimi`): `moonshot-v1-8k`.
- **Gemini** (`AI_PROVIDER=gemini`): Google Generative Language REST API (`gemini-1.5-flash`).
- **OpenRouter** (`AI_PROVIDER=openrouter`): Access many models through `AI_BASE_URL=https://openrouter.ai/api/v1` (for example `AI_MODEL=deepseek/deepseek-chat`).
- **Custom / OpenAI-Compatible** (`AI_PROVIDER=custom`): Set `AI_BASE_URL` to any reverse proxy or local Ollama instance.

Example for **DeepSeek**:
```dotenv
AI_ENABLED=true
AI_PROVIDER=deepseek
AI_API_KEY=sk-your-deepseek-api-key
AI_MODEL=deepseek-chat
```

Example for **Gemini**:
```dotenv
AI_ENABLED=true
AI_PROVIDER=gemini
AI_API_KEY=your-gemini-api-key
AI_MODEL=gemini-1.5-flash
```

---

## 4. Validate & Test

Validate configuration using a transient systemd run:

```bash
sudo systemd-run --wait --pipe --collect \
  -p WorkingDirectory=/opt/server-ai-agent \
  -p User=server-agent -p Group=server-agent \
  -p EnvironmentFile=/etc/server-ai-agent/server-ai-agent.env \
  /opt/server-ai-agent/venv/bin/python -m server_agent --check-config
```
*Expected output: `Configuration OK`*

Send a test notification to your chosen channel:

```bash
sudo systemd-run --wait --pipe --collect \
  -p WorkingDirectory=/opt/server-ai-agent \
  -p User=server-agent -p Group=server-agent \
  -p EnvironmentFile=/etc/server-ai-agent/server-ai-agent.env \
  /opt/server-ai-agent/venv/bin/python -m server_agent --test-notification
```

### Heartbeat Watchdog

The agent refreshes a heartbeat in `state.json` every 30 seconds. `install.sh`
installs and enables `server-ai-agent-watchdog.timer`, which runs
`--check-heartbeat` every 2 minutes:

```bash
sudo systemctl enable --now server-ai-agent-watchdog.timer
sudo systemctl list-timers server-ai-agent-watchdog.timer
```

If the heartbeat is older than `HEARTBEAT_STALE_SECONDS` (default `300`), the
watchdog sends one CRITICAL alert (subject to `ALERT_COOLDOWN_SECONDS`) and
exits. This ensures a crashed or hung agent cannot fail silently. Run the check
manually with:

```bash
sudo systemd-run --wait --pipe --collect \
  -p WorkingDirectory=/opt/server-ai-agent \
  -p User=server-agent -p Group=server-agent \
  -p EnvironmentFile=/etc/server-ai-agent/server-ai-agent.env \
  /opt/server-ai-agent/venv/bin/python -m server_agent --check-heartbeat
```

### Running Once via Cron

If you prefer cron or a systemd timer over a long-running daemon, run a single
cycle with `--once`. It collects and dispatches all incidents, waits for the
alert worker to drain, and exits. The heartbeat is refreshed each run, so the
watchdog timer is not needed in this mode.

```bash
/opt/server-ai-agent/venv/bin/python -m server_agent --once
```

---

## 5. Telegram Alert Format Preview

Alerts are designed for fast mobile triage:

```text
🔴 [app] CRITICAL: Service lshttpd is not active

🖥 app.domain.id · production · 2026-10-26 18:30 UTC
🏷️ Ubuntu 22.04 LTS · CyberPanel · OpenLiteSpeed

📋 Summary
systemd reports lshttpd: failed

🔍 Details
SERVICE: lshttpd  |  STATE: failed  |  EXIT_CODE: 1

🤖 AI Diagnosis & Troubleshooting
🔍 Likely Cause:
Port 80 is already in use or OpenLiteSpeed crashed during configuration reload.

🛠️ Immediate Checks:
• Check port binding: `lsof -i :80 || ss -tulpn | grep :80`
• Check OLS error log: `tail -n 25 /usr/local/lsws/logs/error.log`

💡 Recommended Fix:
Restart via CyberPanel LsWS controller:
`/usr/local/lsws/bin/lswsctrl restart`

⚠️ Risk Assessment:
Web traffic to sites using OpenLiteSpeed will return 502/Connection Refused.

app.domain.id · production
```

---

## 6. Updating an Existing Installation

To update your server with the latest changes:

```bash
cd /tmp/ai-agent-server-monitoring
git pull
sudo ./install.sh
```

Re-running the installer refreshes dependencies, systemd units (including the
watchdog service and timer), and the logrotate policy, while preserving your
existing environment file. Then restart the service and re-enable the timer:

```bash
sudo systemctl restart server-ai-agent
sudo systemctl enable --now server-ai-agent-watchdog.timer
```

View live agent logs:
```bash
sudo tail -f /var/log/server-ai-agent/agent.log
```

---

## Uninstall

Stop and remove the service, watchdog timer, and installed files:

```bash
cd /tmp/ai-agent-server-monitoring
sudo ./uninstall.sh
```

`uninstall.sh --purge` also removes the state/log directories and the
`server-agent` system user. Keep a copy of
`/etc/server-ai-agent/server-ai-agent.env` first if you plan to reinstall.

---

## Troubleshooting

- **Service will not start**: `sudo systemctl status server-ai-agent` and
  `sudo journalctl -u server-ai-agent -n 100 --no-pager`, then run
  `sudo -u server-agent /opt/server-ai-agent/venv/bin/python -m server_agent --check-config`.
- **Logs are unreadable**: grant read access through the distro/panel group
  policy (for example `adm` or `systemd-journal`) or a reviewed ACL. Do not run
  the agent as root.
- **No alerts arrive**: confirm `ALERT_CHANNEL` and credentials, and that the
  incident is not inside `ALERT_COOLDOWN_SECONDS`. Use `--test-notification` to
  verify delivery.
- **SMTP failures**: check host/port and that `SMTP_SECURITY` is `starttls` or
  `ssl`; many providers require an app-specific password.
- **Telegram failures**: confirm the bot is a member/admin of the chat and that
  `TELEGRAM_CHAT_ID` (and the optional topic id) are correct.
- **Heartbeat stale alert**: the agent has not written a heartbeat within
  `HEARTBEAT_STALE_SECONDS`; check the service status and logs above.
- **Required service alerting on a service you do not run**: set
  `SERVICES_REQUIRED` to the exact required list you want (it replaces the
  profile's required list), and set `SERVICES_OPTIONAL` if needed. Alternatively,
  set `SERVICE_PROFILE=none` and list both lists explicitly. Adding a name only
  to `SERVICES_OPTIONAL` does not remove it from the profile's required list.
- **Optional service you do not want monitored**: set `SERVICES_OPTIONAL` to the
  exact optional list you want (it replaces the profile's optional list), or use
  `SERVICE_PROFILE=none` with explicit lists. Required services remain required.
- **Flapping or noisy service alerts**: raise `SERVICE_FAILURE_THRESHOLD` (1-10)
  so a service must stay non-active for more consecutive checks; `failed` units
  still alert immediately. `RECOVERY_ALERTS=false` suppresses recovery notices,
  and `ALERT_COOLDOWN_SECONDS` limits repeat delivery.
- **Verify the effective service plan**: run `--check-config` as shown above and
  inspect the `Service profile`, `Required`, and `Optional` lines, which reflect
  panel auto-detection and all overrides.

---

## Security & Privacy

- The agent is **read-only**: it does not change services, firewall rules, or
  system configuration.
- It runs as the unprivileged `server-agent` user with systemd hardening
  (`ProtectSystem=strict`, `NoNewPrivileges`, restricted address families, and
  a private `/tmp`).
- Log lines and evidence are **redacted locally** (passwords, tokens, keys,
  cookies, connection strings) before any alert or AI request leaves the host.
- When AI enrichment is enabled, only the sanitized incident payload is sent to
  the configured provider. AI output is advisory and cannot trigger commands.
- Prompt-injection defenses treat log content as untrusted data; the AI is
  instructed never to recommend destructive commands.
- The environment file is created with mode `0600`; keep credentials out of git.

---

## Development & CI

Run the agent and its test suite locally without installing the systemd unit:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

python -m pytest -q        # run the test suite
python -m pytest -q --cov=server_agent --cov-report=term-missing  # coverage (fails below 55%)
python -m ruff check .     # lint + import order
pip-audit -r requirements.txt   # audit runtime deps (Python >= 3.10)
python -m server_agent --check-config
```

GitHub Actions (`.github/workflows/ci.yml`) runs on Python 3.9–3.12 for every
push to `main` and every pull request:

- `lint`: `ruff check .`
- `test`: `pytest` with a 55% coverage gate
- `security`: `pip-audit -r requirements.txt`

The runtime only depends on `psutil` and `python-dotenv`; `pytest`,
`pytest-cov`, `ruff`, and `pip-audit` are development-only.

When adding a legacy shim under `server_agent/*.py`, keep intentional
re-exports explicit and silence them with `# noqa: F401` so lint stays green.

---

## Configuration Reference

| Setting | Default | Purpose |
| :--- | :---: | :--- |
| `AUTO_DETECT_ENVIRONMENT` | `true` | Auto-detects OS distro and hosting control panel. |
| `AUTO_DETECT_SERVICES` | `true` | Filters a non-empty legacy `SERVICES` list to installed units. |
| `COLLECT_INCIDENT_EVIDENCE` | `true` | Captures `journalctl` or top process snapshots before AI triage. |
| `EVIDENCE_LINES` | `15` | Number of lines captured for incident evidence. |
| `HEALTH_INTERVAL` | `60` | Health check interval in seconds. |
| `LOG_INTERVAL` | `15` | Log polling interval in seconds. |
| `LOG_FORMAT` | `text` | Log output format: `text` (human-readable) or `json` (one object per line). |
| `HEARTBEAT_STALE_SECONDS` | `300` | Alert if the agent heartbeat is older than this (watchdog timer). |
| `MAX_LOG_LINES_PER_CYCLE` | `250` | Maximum lines processed per file per log cycle. |
| `MAX_LOG_LINE_CHARS` | `4096` | Max characters per physical log line (oversized lines are bounded). |
| `TELEGRAM_MESSAGE_THREAD_ID` | _(unset)_ | Forum topic id for multi-server deployments (one per server). |
| `ESCALATION_CHANNEL` | `none` | Secondary channel for serious incidents: `none` or `telegram`. |
| `ESCALATION_TELEGRAM_BOT_TOKEN` | _(unset)_ | Escalation bot token; falls back to `TELEGRAM_BOT_TOKEN`. |
| `ESCALATION_TELEGRAM_CHAT_ID` | _(unset)_ | Central chat/group id for escalated alerts. |
| `ESCALATION_TELEGRAM_MESSAGE_THREAD_ID` | _(unset)_ | Optional forum topic id for the escalation channel. |
| `ESCALATION_MIN_SEVERITY` | `CRITICAL` | Minimum severity that is also sent to the escalation channel. |
| `LOAD_WARNING_PER_CPU` | `1.5` | 1-minute load average per CPU that triggers a warning. |
| `LOAD_CRITICAL_PER_CPU` | `2.5` | 1-minute load average per CPU that triggers a critical alert. |
| `ALERT_COOLDOWN_SECONDS` | `900` | Cooldown period before repeating an alert with the same fingerprint. |
| `RECOVERY_ALERTS` | `true` | Sends a recovery notice when a metric/service returns to normal. |
| `SSH_FAILED_THRESHOLD` | `5` | Failed attempts before triggering an SSH burst alert. |
| `SSH_FAILED_WINDOW_SECONDS` | `300` | Window in seconds for counting failed SSH logins. |
| `AI_ENABLED` | `false` | Enables multi-provider AI triage enrichment. |
| `AI_PROVIDER` | `deepseek` | Selected AI provider (`deepseek`, `openai`, `claude`, `gemini`, etc.). |
| `AI_RATE_LIMIT_PER_MINUTE` | `10` | Max AI enrichment requests per minute (sliding window). |
| `SERVER_NAME` | auto-detected | Stable display name used in alerts and fingerprints. |
| `ENVIRONMENT` | `production` | Environment label shown in alert headers/footers. |
| `ALERT_CHANNEL` | `email` | Primary delivery channel: `email` or `telegram`. |
| `SERVICES` | _(unset)_ | Legacy comma-separated watch list; when set, replaces the profile and is auto-filtered to installed units. |
| `SERVICE_PROFILE` | `auto` | Per-panel service profile: `auto`, `none`, or a panel name. |
| `SERVICES_REQUIRED` | _(unset)_ | Overrides the profile's required service list. |
| `SERVICES_OPTIONAL` | _(unset)_ | Overrides the profile's optional service list. |
| `SERVICE_FAILURE_THRESHOLD` | `2` | Consecutive non-active checks before alerting (`failed` alerts immediately). |
| `CPU_WARNING` | `85` | CPU usage percentage that triggers a warning. |
| `CPU_CRITICAL` | `95` | CPU usage percentage that triggers a critical alert. |
| `MEMORY_WARNING` | `85` | Memory usage percentage that triggers a warning. |
| `MEMORY_CRITICAL` | `95` | Memory usage percentage that triggers a critical alert. |
| `DISK_WARNING` | `85` | Disk usage percentage that triggers a warning. |
| `DISK_CRITICAL` | `95` | Disk usage percentage that triggers a critical alert. |
| `DISK_PATHS` | `/` | Comma-separated mount points to monitor. |
| `ALERT_ON_MISSING_SERVICE` | `false` | Alert (`WARNING`) when an optional service's state is unknown. |
| `WEB_ERROR_LOGS` | _(unset)_ | Extra absolute web error-log paths (max 12). |
| `NGINX_ERROR_LOG` | `/var/log/nginx/error.log` | Nginx error log path. |
| `APACHE_ERROR_LOG` | `/var/log/apache2/error.log` | Debian/Ubuntu Apache error log path. |
| `APACHE_RHEL_ERROR_LOG` | `/var/log/httpd/error_log` | RHEL-family Apache error log path. |
| `WEB_ERROR_BATCH_THRESHOLD` | `1` | Minimum matching lines before a web alert fires. |
| `MAX_LOG_SAMPLE_CHARS` | `600` | Max characters retained per log sample. |
| `AUTH_LOG` | `/var/log/auth.log` | Debian/Ubuntu SSH auth log path. |
| `AUTH_LOG_RHEL` | `/var/log/secure` | RHEL-family SSH auth log path. |
| `SSH_FAILURE_TRACKED_IPS_MAX` | `1000` | Max source IPs tracked for brute-force counting. |
| `SSH_ALERT_SUCCESS` | `true` | Alert on successful SSH logins (root logins are critical). |
| `SSH_ALERT_FAILED_BURST` | `true` | Alert when failed logins cross the threshold. |
| `SSH_ALERT_ROOT_LOGIN` | `true` | Treat root SSH logins as critical. |
| `TRUSTED_SSH_NETWORKS` | _(unset)_ | Comma-separated CIDRs that downgrade login alerts. |
| `KERNEL_MONITOR_ENABLED` | `true` | Enable OOM/kernel-crash log monitoring. |
| `KERNEL_LOG` | `/var/log/kern.log` | Debian/Ubuntu kernel log path. |
| `KERNEL_LOG_RHEL` | `/var/log/messages` | RHEL-family kernel log path. |
| `KERNEL_ERROR_LOGS` | _(unset)_ | Extra absolute kernel log paths (max 6). |
| `KERNEL_JOURNAL_FALLBACK` | `true` | Use `journalctl -k` when no kernel log file exists. |
| `SMTP_HOST` | _(unset)_ | SMTP relay host. |
| `SMTP_PORT` | `587` | SMTP relay port. |
| `SMTP_SECURITY` | `starttls` | SMTP security mode: `starttls` or `ssl`. |
| `SMTP_USERNAME` | _(unset)_ | SMTP login user (optional). |
| `SMTP_PASSWORD` | _(unset)_ | SMTP login password (optional). |
| `SMTP_FROM` | _(unset)_ | From address for alert email. |
| `SMTP_TO` | _(unset)_ | Comma-separated recipient addresses. |
| `SMTP_TIMEOUT` | `20` | SMTP connection timeout in seconds. |
| `TELEGRAM_BOT_TOKEN` | _(unset)_ | Telegram bot token. |
| `TELEGRAM_CHAT_ID` | _(unset)_ | Target chat/group/supergroup id. |
| `TELEGRAM_TIMEOUT` | `10` | Telegram API timeout in seconds. |
| `AI_API_KEY` | _(unset)_ | API key for the selected AI provider. |
| `AI_MODEL` | provider default | Model override for the selected provider. |
| `AI_BASE_URL` | provider default | Base URL override (required for `custom`). |
| `AI_TIMEOUT_SECONDS` | `10` | AI request timeout in seconds. |
| `AI_MAX_OUTPUT_TOKENS` | `400` | Max output tokens requested from the provider. |
| `STATE_DIR` | `/var/lib/server-ai-agent` | Directory for persisted cursors, cooldowns, and heartbeat. |
| `LOG_FILE` | `/var/log/server-ai-agent/agent.log` | Agent log file path. |
| `LOG_LEVEL` | `INFO` | Log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |

---

## License

This project is licensed under the Apache 2.0 License. See [LICENSE](LICENSE).
