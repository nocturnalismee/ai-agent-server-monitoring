# Security & Reliability Hardening Plan

> **For agentic workers:** execute batch-by-batch with TDD. Each batch ends with full pytest + ruff + commit.

**Goal:** Close AI/notification data-leak paths, then make alerting and operations production-grade.

**Architecture:** Local redaction is the trust boundary; every outbound payload (AI, Telegram, SMTP) must pass through it. Alert pipeline gets global rate limiting, per-monitor isolation, and durable delivery. Operations get self-observability and atomic upgrades.

**Tech Stack:** Python 3.9+, psutil, python-dotenv (no new runtime deps).

**Spec:** this plan + the 2026-10-28 audit findings.

## Global Constraints
- Python 3.9 compatible (`from __future__ import annotations`, `typing.Optional/List/Dict/Tuple`).
- `ruff check .` clean, line length 100, no new runtime dependencies.
- Agent stays read-only (never start/stop/restart/enable services).
- Never log secrets; redaction must run before AI/notify/persist.
- Existing behavior/tests must keep passing unless a change is explicitly required.
- Commit per batch; do not push until the batch review passes.

---

## Batch A — Security: redaction + AI data boundaries

### A1. Redaction coverage (`server_agent/core/redaction.py`)
- `_CONNECTION_PASSWORD` scheme-agnostic: `r"(\b[a-zA-Z][a-zA-Z0-9+.-]*://[^:/\s@]+:)[^@\s/]+(@"` (covers `mongodb+srv://`, `https://user:pass@`).
- `_HEADER_SECRET` must match mid-line and redact the whole value: `(?im)(\b(?:proxy-)?authorization|\b(?:set-)?cookie|\bx-api-key|\bx-auth-token)\s*:\s*[^\r\n]+` (redact value after the colon; keep header name).
- `_ASSIGNMENT_SECRET`: allow optional quotes around the key, JSON `"key": "value"`, and keywords: `api_key`, `access_token`, `refresh_token`, `token`, `password`, `passwd`, `pass`, `passphrase`, `pwd`, `secret`, `secret_key`, `client_secret`, `credential`, `session`, `cookie`, `private_key`, `database_url`, `dsn`, `db_pass`, `aws_secret_access_key`, `aws_access_key_id`.
- `_PRIVATE_KEY`: redact truncated blocks (BEGIN without END) through end of string.
- `_API_TOKEN`: add `sk_live_[A-Za-z0-9]{16,}` and `AIza[0-9A-Za-z_-]{35}`.
- Keep `sanitize_text` order; add tests for every case in the audit matrix (mongodb+srv, https DSN, db_pass, JSON password, aws key, mid-line Set-Cookie keeps no session id, mid-line Authorization Basic, truncated private key, sk_live, AIza, bare hex signature may remain — document as accepted).

### A2. AI boundary hardening
- `ai/analyzer.py`: remove `?key={self.api_key}` from the Gemini URL; keep `x-goog-api-key` header.
- `core/config.py` `validate()`: reject non-`https://` `AI_BASE_URL` unless host is `localhost`, `127.0.0.1`, or `[::1]`.
- `ai/analyzer.py`: sanitize provider error-body excerpt with `sanitize_text(...)[0][:200]` before logging.
- `core/redaction.py` `sanitize_incident`: also sanitize `fingerprint`.
- `agent.py` `_process`: sanitize the AI result inline before assigning (`sanitize_text(...)[0]`), keeping the later re-sanitize.
- `core/logging_setup.py`: best-effort `chmod 0600` on the log file.
- `core/state.py` `__init__`: best-effort `chmod 0700` on the state dir.

### A3. Payload size caps
- `collectors/evidence.py`: per-line ≤2000 chars, total ≤16 KB, with truncation marker.
- `notifiers/emailer.py`: cap text and HTML bodies at 64 KB, with marker.

**Acceptance:** new tests prove each leak case is redacted, Gemini URL has no key, http base URL is rejected, evidence/email are bounded; full suite + ruff clean. Commit `fix: harden redaction and AI data boundaries`.

---

## Batch B — Reliability (outline; detail when reached)
- Per-monitor `try/except`; always advance schedule markers (no 1 Hz hot loop).
- Web fingerprint `web:{server}` only; categories stay in details.
- Clear alert cooldown on recovery so a new outage re-alerts.
- Global alert rate limiter; Telegram 429 `Retry-After` backoff.
- Clock handling: negative/future timestamps must not suppress or fabricate alerts.

## Batch C — Operations (outline)
- `status.json` + `--status`; `--version` from one source.
- systemd `MemoryMax`/`TasksMax`/`CPUQuota`/`StartLimit*`.
- Spool + retry for undeliverable one-shot incidents.
- `flock` around state load-modify-save.
- Fail-soft config for non-critical values.
- Atomic install (`try-restart`, versioned dir/symlink) + lockfile/offline option.
- CI: RHEL-family leg + `shellcheck` + corrupt-state/rotation tests.

## Batch D — Optional (outline)
- `AI_SEND_SAMPLES` / `AI_SEND_EVIDENCE` opt-outs.
- Untrusted-log delimiters + destructive-command denylist in Telegram rendering.
- Batched `systemctl show` per cycle.
- `Type=notify` + `WatchdogSec` via sd_notify.
