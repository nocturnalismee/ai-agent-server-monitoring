# AI Agent Server Monitoring

A read-only, high-performance Linux health, security, and log monitoring agent for **Ubuntu/Debian**, **AlmaLinux/RHEL**, and **CloudLinux**, with built-in auto-discovery and context awareness for hosting control panels: **cPanel/WHM**, **aaPanel**, **CyberPanel**, **CloudPanel**, **Plesk**, and **DirectAdmin**.

It monitors host health and selected logs, collects real-time diagnostic evidence (`journalctl` / top processes), and sends alerts through **one** chosen channel: **SMTP email** or **Telegram**. High-severity incidents are enriched with multi-provider AI triage (DeepSeek, OpenAI, Claude, Groq, Kimi, or Gemini) using the official HTTPS REST API through Python's standard library—**no third-party AI SDKs are required**.

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
- Configures systemd service and logrotate.

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

# Auto-discover installed services to eliminate false alerts for services not installed
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
sudo cp -a server_agent /opt/server-ai-agent/
sudo systemctl restart server-ai-agent
```

View live agent logs:
```bash
sudo tail -f /var/log/server-ai-agent/agent.log
```

---

## Development & CI

Run the agent and its test suite locally without installing the systemd unit:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

python -m pytest -q        # run the test suite
python -m ruff check .     # lint + import order
python -m server_agent --check-config
```

GitHub Actions (`.github/workflows/ci.yml`) runs `ruff check .` and the pytest
suite on Python 3.9–3.12 for every push to `main` and every pull request. The
runtime only depends on `psutil` and `python-dotenv`; `pytest` and `ruff` are
development-only.

When adding a legacy shim under `server_agent/*.py`, keep intentional
re-exports explicit and silence them with `# noqa: F401` so lint stays green.

---

## Configuration Reference

| Setting | Default | Purpose |
| :--- | :---: | :--- |
| `AUTO_DETECT_ENVIRONMENT` | `true` | Auto-detects OS distro and hosting control panel. |
| `AUTO_DETECT_SERVICES` | `true` | Filters watch list to include only installed services. |
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

---

## License

This project is licensed under the Apache 2.0 License.
