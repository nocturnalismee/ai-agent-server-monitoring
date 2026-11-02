from __future__ import annotations

import argparse
import json
import os
import queue
import signal
import socket
import sys
import tempfile
import threading
import time
from collections import deque
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import __version__
from .ai.analyzer import AIAnalyzer
from .collectors.evidence import EvidenceCollector
from .collectors.filetail import FileTailer
from .core.config import Config
from .core.logging_setup import setup_logging
from .core.models import Incident
from .core.redaction import sanitize_incident, sanitize_text
from .core.spool import IncidentSpool
from .core.state import StateStore
from .detectors.environment import EnvironmentDetector
from .detectors.service_profiles import profile_name, resolve_targets
from .detectors.services import ServiceDetector
from .monitors.health import HealthMonitor
from .monitors.kernel import KernelMonitor
from .monitors.ssh import SSHMonitor
from .monitors.web import WebLogMonitor
from .notifiers.emailer import EmailNotifier
from .notifiers.telegram import TelegramNotifier

# How often the running agent refreshes its heartbeat timestamp.
_HEARTBEAT_WRITE_SECONDS = 30.0
_HEARTBEAT_FINGERPRINT = "agent:heartbeat"


def _sd_notify(message: str) -> None:
    """Best-effort systemd readiness/watchdog notification."""
    path = os.environ.get("NOTIFY_SOCKET")
    if not path or not hasattr(socket, "AF_UNIX"):
        return
    if path.startswith("@"):
        path = "\0" + path[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(path)
            sock.sendall(message.encode("utf-8"))
    except OSError:
        pass
_ALERT_RATE_WINDOW_SECONDS = 60.0
_SPOOL_RETRY_SECONDS = 30.0
_SEVERITY_RANK = {"INFO": 0, "WARNING": 1, "CRITICAL": 2}
_DEFAULT_STATE_DIR = Path("/var/lib/server-ai-agent")
_COUNTER_NAMES = ("seen", "sent", "suppressed", "dropped", "delivery_errors")


def _status_path() -> Path:
    return Path(os.getenv("STATE_DIR", str(_DEFAULT_STATE_DIR))) / "status.json"


def _atomic_write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".status-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _print_status() -> int:
    path = _status_path()
    try:
        sys.stdout.write(path.read_text())
    except (OSError, UnicodeError):
        print(f"No status available at {path}", file=sys.stderr)
        return 1
    return 0


def _severity_at_least(severity: str, minimum: str) -> bool:
    return _SEVERITY_RANK.get(severity.upper(), 0) >= _SEVERITY_RANK.get(
        minimum.upper(), 2
    )


def _incident_from_dict(data) -> Incident:
    if not isinstance(data, dict):
        raise ValueError("invalid spooled incident")
    values = {
        key: data[key]
        for key in (
            "kind",
            "severity",
            "title",
            "summary",
            "fingerprint",
            "details",
            "timestamp",
            "ai_analysis",
            "evidence",
        )
        if key in data
    }
    for key in ("kind", "severity", "title", "summary", "fingerprint"):
        if not isinstance(values.get(key), str):
            raise ValueError(f"spooled incident is missing {key}")
    if not isinstance(values.get("details"), dict):
        values["details"] = {}
    return Incident(**values)


def _build_notifier(cfg, log, metadata=None):
    """Create the primary notifier plus an optional critical-channel escalation."""
    if cfg.alert_channel == "email":
        primary = EmailNotifier(cfg, log, metadata=metadata)
    else:
        primary = TelegramNotifier(cfg, log, metadata=metadata)

    escalation = None
    if cfg.escalation_channel == "telegram":
        token = cfg.escalation_telegram_bot_token or cfg.telegram_bot_token
        escalation_cfg = replace(
            cfg,
            telegram_bot_token=token,
            telegram_chat_id=cfg.escalation_telegram_chat_id,
            telegram_message_thread_id=cfg.escalation_telegram_message_thread_id,
        )
        escalation = TelegramNotifier(escalation_cfg, log, metadata=metadata)
    return primary, escalation


def _parse_heartbeat(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _heartbeat_age_seconds(
    value: Optional[str], now: Optional[datetime] = None
) -> Optional[float]:
    """Return the heartbeat age in seconds, or None when absent/unparseable."""
    parsed = _parse_heartbeat(value)
    if parsed is None:
        return None
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return max((current - parsed).total_seconds(), 0.0)


def _heartbeat_is_stale(
    value: Optional[str], stale_seconds: int, now: Optional[datetime] = None
) -> bool:
    age = _heartbeat_age_seconds(value, now)
    if age is None:
        return True
    return age > stale_seconds


def _check_heartbeat(cfg: Config) -> int:
    """One-shot watchdog check used by systemd. Alerts when the agent is stale."""
    cfg, warnings = cfg.normalized()
    for warning in warnings:
        print(f"Configuration warning: {warning}", file=sys.stderr)
    cfg.validate()
    log = setup_logging(cfg.log_file, cfg.log_level, cfg.log_format)
    state = StateStore(
        cfg.state_dir,
        cfg.ssh_failure_tracked_ips_max,
        cfg.ssh_failed_threshold,
    )
    watchdog_state = StateStore(
        cfg.state_dir,
        cfg.ssh_failure_tracked_ips_max,
        cfg.ssh_failed_threshold,
        filename="watchdog-alert.json",
    )
    heartbeat = state.heartbeat()
    age = _heartbeat_age_seconds(heartbeat)
    if age is not None and age <= cfg.heartbeat_stale_seconds:
        print(f"Heartbeat OK ({age:.0f}s old).")
        return 0

    detail = (
        "missing"
        if age is None
        else f"{age:.0f}s old (limit {cfg.heartbeat_stale_seconds}s)"
    )
    if not watchdog_state.can_alert(
        _HEARTBEAT_FINGERPRINT, cfg.alert_cooldown_seconds
    ):
        print(f"Heartbeat stale ({detail}); alert already sent recently.")
        return 0

    metadata = EnvironmentDetector(log).detect() if cfg.auto_detect_environment else None
    notifier, escalation = _build_notifier(cfg, log, metadata=metadata)

    incident = Incident(
        kind="agent",
        severity="CRITICAL",
        title="Monitoring agent heartbeat is stale",
        summary=(
            f"The monitoring agent on {cfg.server_name} has not updated its heartbeat "
            f"recently ({detail}). It may have crashed or hung. Check "
            "`systemctl status server-ai-agent` and recent agent logs."
        ),
        fingerprint=_HEARTBEAT_FINGERPRINT,
        details={
            "heartbeat": heartbeat or "missing",
            "age_seconds": f"{age:.0f}" if age is not None else "unknown",
            "stale_limit_seconds": cfg.heartbeat_stale_seconds,
        },
    )
    external = sanitize_incident(incident)
    delivered = notifier.send(external)
    if escalation is not None and _severity_at_least(
        incident.severity, cfg.escalation_min_severity
    ):
        if escalation.send(external):
            delivered = True
    if not delivered:
        print(f"Heartbeat stale ({detail}); failed to send alert.", file=sys.stderr)
        return 1
    watchdog_state.mark_alert_sent(
        _HEARTBEAT_FINGERPRINT, cfg.alert_cooldown_seconds
    )
    print(f"Heartbeat stale ({detail}); alert sent.")
    return 0


class Agent:
    def __init__(self, cfg: Config):
        cfg.validate()
        self.cfg = cfg
        self.log = setup_logging(cfg.log_file, cfg.log_level, cfg.log_format)

        # Detect server OS, control panel, web & database stack
        self.env_detector = EnvironmentDetector(self.log)
        self.metadata = (
            self.env_detector.detect()
            if getattr(cfg, "auto_detect_environment", True)
            else None
        )

        self.state = StateStore(
            cfg.state_dir,
            cfg.ssh_failure_tracked_ips_max,
            cfg.ssh_failed_threshold,
        )
        self.spool = IncidentSpool(cfg.state_dir, logger=self.log)
        self.tailer = FileTailer(self.state, self.log)
        self.evidence_collector = (
            EvidenceCollector(max_lines=getattr(cfg, "evidence_lines", 15), logger=self.log)
            if getattr(cfg, "collect_incident_evidence", True)
            else None
        )

        self.health = HealthMonitor(
            cfg,
            self.state,
            self.log,
            panel=self.metadata.panel if self.metadata else None,
        )
        self.web = WebLogMonitor(cfg, self.tailer, self.log)
        self.ssh = SSHMonitor(cfg, self.state, self.tailer, self.log)
        self.kernel = KernelMonitor(cfg, self.state, self.tailer, self.log)

        self.ai = AIAnalyzer(cfg, self.log, metadata=self.metadata)
        self.notifier, self.escalation_notifier = _build_notifier(
            cfg, self.log, metadata=self.metadata
        )
        self.running = True
        self.counters = {name: 0 for name in _COUNTER_NAMES}
        self._counter_lock = threading.Lock()
        self.cycle_durations_ms = {"health": 0.0, "logs": 0.0}

        # Alerts (evidence collection, AI triage, delivery) may block on network
        # I/O. Process them on a single background worker so monitoring cycles
        # are never stalled. A single worker keeps shared state free of races.
        self._alert_queue: "queue.Queue[object]" = queue.Queue(maxsize=1000)
        self._alert_stop = object()
        self._alert_send_times: "deque[float]" = deque()
        self._alert_worker = threading.Thread(
            target=self._alert_worker_loop,
            name="alert-worker",
            daemon=True,
        )
        self._alert_worker.start()

    def stop(self, *_):
        self.running = False

    def _count(self, name: str) -> None:
        lock = getattr(self, "_counter_lock", None)
        if lock is None:
            lock = threading.Lock()
            self._counter_lock = lock
        with lock:
            counters = getattr(self, "counters", None)
            if counters is None:
                counters = {key: 0 for key in _COUNTER_NAMES}
                self.counters = counters
            counters[name] += 1

    def _durations(self):
        durations = getattr(self, "cycle_durations_ms", None)
        if durations is None:
            durations = {"health": 0.0, "logs": 0.0}
            self.cycle_durations_ms = durations
        return durations

    def _counter_snapshot(self):
        counters = getattr(self, "counters", None)
        if counters is None:
            counters = {key: 0 for key in _COUNTER_NAMES}
            self.counters = counters
        lock = getattr(self, "_counter_lock", None)
        if lock is None:
            return {key: int(counters.get(key, 0)) for key in _COUNTER_NAMES}
        with lock:
            return {key: int(counters.get(key, 0)) for key in _COUNTER_NAMES}

    def dispatch(self, incident):
        """Queue an incident for asynchronous processing."""
        self._count("seen")
        try:
            self._alert_queue.put_nowait(incident)
        except queue.Full:
            self._count("dropped")
            self._spool_incident(incident)
            self.log.warning(
                "Alert queue full; dropping incident: %s", incident.fingerprint
            )

    def _alert_worker_loop(self):
        last_spool_retry = time.monotonic()
        while True:
            got_item = False
            item = None
            try:
                item = self._alert_queue.get(timeout=1.0)
                got_item = True
            except queue.Empty:
                pass
            try:
                if item is self._alert_stop:
                    return
                if got_item:
                    self._process(item)
            except Exception:
                self.log.exception("Alert dispatch error")
            finally:
                if got_item:
                    self._alert_queue.task_done()

            now = time.monotonic()
            if now - last_spool_retry >= _SPOOL_RETRY_SECONDS:
                last_spool_retry = now
                try:
                    self._retry_spooled()
                except Exception:
                    self.log.exception("Spool retry error")

    def _alert_rate_limited(self) -> bool:
        limit = int(getattr(self.cfg, "alert_rate_limit_per_minute", 0) or 0)
        if limit <= 0:
            return False
        times = getattr(self, "_alert_send_times", None)
        if times is None:
            times = deque()
            self._alert_send_times = times
        now = time.monotonic()
        cutoff = now - _ALERT_RATE_WINDOW_SECONDS
        while times and times[0] <= cutoff:
            times.popleft()
        return len(times) >= limit

    def _record_alert_send(self) -> None:
        limit = int(getattr(self.cfg, "alert_rate_limit_per_minute", 0) or 0)
        if limit <= 0:
            return
        times = getattr(self, "_alert_send_times", None)
        if times is None:
            times = deque()
            self._alert_send_times = times
        times.append(time.monotonic())

    def _process(self, incident):
        # Security logins are intentionally unique per user/IP but still cooldown-protected.
        if not self.state.can_alert(
            incident.fingerprint, self.cfg.alert_cooldown_seconds
        ):
            self._count("suppressed")
            self.log.info("Suppressed duplicate alert: %s", incident.fingerprint)
            return

        if self._alert_rate_limited():
            self._count("dropped")
            self._spool_incident(incident)
            self.log.warning(
                "Alert rate limit reached; dropping alert: %s", incident.fingerprint
            )
            return

        # Collect real-time diagnostic evidence logs before notifying or asking AI
        if self.evidence_collector and not getattr(incident, "evidence", ""):
            incident.evidence = self.evidence_collector.collect(incident)

        # Source logs remain local. Only this safe copy can leave the server.
        external_incident = sanitize_incident(incident)

        # AI is enrichment only; alerting must never depend on it.
        if incident.severity in {"WARNING", "CRITICAL"}:
            try:
                external_incident.ai_analysis = sanitize_text(
                    self.ai.analyze(external_incident)
                )[0]
                external_incident = sanitize_incident(external_incident)
            except Exception:
                self.log.exception("AI analysis failed; sending alert without it")

        # A failed delivery must not suppress the next alert.
        self._record_alert_send()
        delivered = False
        delivery_error = False
        try:
            delivered = bool(self.notifier.send(external_incident))
        except Exception:
            delivery_error = True
            self.log.exception("Primary notification failed")
        if self.escalation_notifier is not None and _severity_at_least(
            incident.severity, self.cfg.escalation_min_severity
        ):
            try:
                if self.escalation_notifier.send(external_incident):
                    delivered = True
            except Exception:
                delivery_error = True
                self.log.exception("Escalation notification failed")
        if delivered:
            self._count("sent")
            self.state.mark_alert_sent(
                incident.fingerprint, self.cfg.alert_cooldown_seconds
            )
            self._remove_spooled(external_incident.fingerprint)
        else:
            self._count("delivery_errors")
            self._spool_incident(external_incident)
        if delivery_error and delivered:
            self._count("delivery_errors")

    def _remove_spooled(self, fingerprint: str) -> None:
        spool = getattr(self, "spool", None)
        if spool is None:
            return
        try:
            spool.remove(IncidentSpool.key_for(fingerprint))
        except Exception:
            debug = getattr(getattr(self, "log", None), "debug", None)
            if debug is not None:
                debug("Failed to remove spooled incident", exc_info=True)

    def _spool_incident(self, incident) -> None:
        spool = getattr(self, "spool", None)
        if spool is None:
            return
        try:
            spool.add(sanitize_incident(incident))
        except Exception:
            debug = getattr(getattr(self, "log", None), "debug", None)
            if debug is not None:
                debug("Failed to spool incident", exc_info=True)

    def _retry_spooled(self) -> None:
        spool = getattr(self, "spool", None)
        if spool is None:
            return
        for key, payload, _attempts in spool.due():
            try:
                incident = sanitize_incident(_incident_from_dict(payload))
            except Exception:
                debug = getattr(getattr(self, "log", None), "debug", None)
                if debug is not None:
                    debug("Discarding corrupt spooled incident: %s", key)
                spool.remove(key)
                continue

            if not self.state.can_alert(
                incident.fingerprint, self.cfg.alert_cooldown_seconds
            ):
                debug = getattr(getattr(self, "log", None), "debug", None)
                if debug is not None:
                    debug("Discarding superseded spooled incident: %s", key)
                spool.remove(key)
                continue

            if self._alert_rate_limited():
                debug = getattr(getattr(self, "log", None), "debug", None)
                if debug is not None:
                    debug("Alert rate limit reached; deferring spooled incident: %s", key)
                break
            self._record_alert_send()

            delivered = False
            delivery_error = False
            try:
                delivered = bool(self.notifier.send(incident))
            except Exception:
                delivery_error = True
                self.log.exception("Spooled notification failed")
            if self.escalation_notifier is not None and _severity_at_least(
                incident.severity, self.cfg.escalation_min_severity
            ):
                try:
                    if self.escalation_notifier.send(incident):
                        delivered = True
                except Exception:
                    delivery_error = True
                    self.log.exception("Spooled escalation failed")

            if delivered:
                self._count("sent")
                self.state.mark_alert_sent(
                    incident.fingerprint, self.cfg.alert_cooldown_seconds
                )
                spool.remove(key)
            else:
                self._count("delivery_errors")
                spool.mark_attempt(key)
            if delivery_error and delivered:
                self._count("delivery_errors")

    def drain(self):
        """Block until every queued incident has been processed."""
        self._alert_queue.join()

    def _shutdown_worker(self, timeout: float = 15.0):
        """Flush queued alerts, then stop the worker and release resources."""
        try:
            self._alert_queue.put(self._alert_stop, timeout=5.0)
        except queue.Full:
            self.log.warning("Alert queue full during shutdown; worker not stopped")
        self._alert_worker.join(timeout=timeout)
        if self._alert_worker.is_alive():
            self.log.warning("Alert worker did not stop within %.0fs", timeout)
        self.ai.close()

    def _run_monitor(self, name, monitor):
        try:
            for incident in monitor.collect():
                self.dispatch(incident)
        except Exception:
            self.log.exception("Monitor failed: %s", name)

    def _run_group(self, monitors):
        started = time.monotonic()
        for name, monitor in monitors:
            self._run_monitor(name, monitor)
        return round((time.monotonic() - started) * 1000, 2)

    def _write_status(self) -> None:
        try:
            cfg = getattr(self, "cfg", None)
            state_dir = getattr(cfg, "state_dir", None) if cfg is not None else None
            if state_dir is None:
                return
            now = datetime.now(timezone.utc).isoformat()
            durations = self._durations()
            payload = {
                "version": __version__,
                "server_name": cfg.server_name,
                "updated_at": now,
                "last_cycle_ts": now,
                "cycle_durations_ms": {
                    "health": durations.get("health", 0.0),
                    "logs": durations.get("logs", 0.0),
                },
                "queue_depth": int(self._alert_queue.qsize()),
                "counters": self._counter_snapshot(),
            }
            _atomic_write_json(Path(state_dir) / "status.json", payload)
        except Exception:
            debug = getattr(getattr(self, "log", None), "debug", None)
            if debug is not None:
                debug("Failed to write status.json", exc_info=True)

    def run_once(self):
        try:
            try:
                self.state.set_heartbeat()
            except Exception:
                self.log.exception("Failed to update heartbeat")
            self.cycle_durations_ms = {
                "health": self._run_group([("health", self.health)]),
                "logs": self._run_group(
                    [("web", self.web), ("ssh", self.ssh), ("kernel", self.kernel)]
                ),
            }
            self.drain()
        finally:
            self._write_status()

    def run(self):
        badge = f" [{self.metadata.badge()}]" if self.metadata else ""
        self.log.info(
            "Server AI Agent started server=%s env=%s%s",
            self.cfg.server_name,
            self.cfg.environment,
            badge,
        )
        _sd_notify("READY=1")
        last_health = 0.0
        last_logs = 0.0
        try:
            self.state.set_heartbeat()
        except Exception:
            self.log.exception("Failed to update heartbeat")
        last_heartbeat = time.monotonic()

        while self.running:
            now = time.monotonic()
            _sd_notify("WATCHDOG=1")
            if now - last_heartbeat >= _HEARTBEAT_WRITE_SECONDS:
                try:
                    self.state.set_heartbeat()
                    last_heartbeat = now
                except Exception:
                    self.log.exception("Failed to update heartbeat")
            ran = False
            if now - last_health >= self.cfg.health_interval:
                # Advance first: a failing collector must wait for its next
                # interval instead of retrying at the 1 Hz loop rate.
                last_health = now
                self._durations()["health"] = self._run_group(
                    [("health", self.health)]
                )
                ran = True

            if now - last_logs >= self.cfg.log_interval:
                last_logs = now
                self._durations()["logs"] = self._run_group(
                    [("web", self.web), ("ssh", self.ssh), ("kernel", self.kernel)]
                )
                ran = True

            if ran:
                self._write_status()

            time.sleep(1)

        self._shutdown_worker()
        self.log.info("Server AI Agent stopped")


def _print_service_plan(cfg) -> None:
    legacy = list(cfg.services)
    if legacy and getattr(cfg, "auto_detect_services", True):
        legacy = ServiceDetector(None).filter_installed_services(legacy)
    panel = None
    if (
        cfg.service_profile == "auto"
        and not legacy
        and getattr(cfg, "auto_detect_environment", False)
    ):
        try:
            panel = EnvironmentDetector(None).detect().panel
        except Exception:
            panel = None
    required, optional = resolve_targets(
        cfg.service_profile,
        panel,
        legacy,
        cfg.services_required,
        cfg.services_optional,
    )
    mode = "auto" if cfg.service_profile == "auto" else "explicit"
    print(f"Service profile: {profile_name(cfg.service_profile, panel)} ({mode})")
    print("Required: " + (", ".join(required) if required else "(none)"))
    print("Optional: " + (", ".join(optional) if optional else "(none)"))


def main():
    parser = argparse.ArgumentParser(description="Read-only AI server health/security monitor")
    parser.add_argument("--once", action="store_true", help="Run one monitoring cycle and exit")
    parser.add_argument("--test-notification", action="store_true", help="Send a test alert through the selected channel and exit")
    parser.add_argument("--test-email", action="store_true", help="Deprecated alias for --test-notification when email is selected")
    parser.add_argument("--check-config", action="store_true", help="Validate config and exit")
    parser.add_argument("--check-heartbeat", action="store_true", help="Run the heartbeat watchdog and exit")
    parser.add_argument("--status", action="store_true", help="Print the last cycle status and exit")
    parser.add_argument("--version", action="store_true", help="Print the agent version and exit")
    args = parser.parse_args()

    if args.version:
        print(f"server-ai-agent {__version__}")
        return 0

    if args.status:
        return _print_status()

    try:
        cfg = Config()
        cfg, warnings = cfg.normalized()
        for warning in warnings:
            print(f"Configuration warning: {warning}", file=sys.stderr)
        cfg.validate()
    except Exception as exc:
        print(f"Configuration/startup error: {exc}", file=sys.stderr)
        return 2

    if args.check_config:
        print("Configuration OK")
        _print_service_plan(cfg)
        return 0

    if args.check_heartbeat:
        try:
            return _check_heartbeat(cfg)
        except Exception as exc:
            print(f"Heartbeat check error: {exc}", file=sys.stderr)
            return 2

    try:
        agent = Agent(cfg)
    except Exception as exc:
        print(f"Configuration/startup error: {exc}", file=sys.stderr)
        return 2
    if args.test_email and cfg.alert_channel != "email":
        print("Configuration/startup error: --test-email requires ALERT_CHANNEL=email", file=sys.stderr)
        return 2
    if args.test_notification or args.test_email:
        ok = agent.notifier.send_test()
        if agent.escalation_notifier is not None:
            ok = agent.escalation_notifier.send_test() and ok
        return 0 if ok else 1
    if args.once:
        agent.run_once()
        return 0

    signal.signal(signal.SIGTERM, agent.stop)
    signal.signal(signal.SIGINT, agent.stop)
    agent.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
