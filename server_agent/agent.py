from __future__ import annotations

import argparse
import queue
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from .ai.analyzer import AIAnalyzer
from .collectors.evidence import EvidenceCollector
from .collectors.filetail import FileTailer
from .core.config import Config
from .core.logging_setup import setup_logging
from .core.models import Incident
from .core.redaction import sanitize_incident
from .core.state import StateStore
from .detectors.environment import EnvironmentDetector
from .monitors.health import HealthMonitor
from .monitors.kernel import KernelMonitor
from .monitors.ssh import SSHMonitor
from .monitors.web import WebLogMonitor
from .notifiers.emailer import EmailNotifier
from .notifiers.telegram import TelegramNotifier

# How often the running agent refreshes its heartbeat timestamp.
_HEARTBEAT_WRITE_SECONDS = 30.0
_HEARTBEAT_FINGERPRINT = "agent:heartbeat"


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
    return (current - parsed).total_seconds()


def _heartbeat_is_stale(
    value: Optional[str], stale_seconds: int, now: Optional[datetime] = None
) -> bool:
    age = _heartbeat_age_seconds(value, now)
    if age is None:
        return True
    return age > stale_seconds


def _check_heartbeat(cfg: Config) -> int:
    """One-shot watchdog check used by systemd. Alerts when the agent is stale."""
    log = setup_logging(cfg.log_file, cfg.log_level)
    state = StateStore(
        cfg.state_dir,
        cfg.ssh_failure_tracked_ips_max,
        cfg.ssh_failed_threshold,
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
    if not state.can_alert(_HEARTBEAT_FINGERPRINT, cfg.alert_cooldown_seconds):
        print(f"Heartbeat stale ({detail}); alert already sent recently.")
        return 0

    metadata = EnvironmentDetector(log).detect() if cfg.auto_detect_environment else None
    if cfg.alert_channel == "email":
        notifier = EmailNotifier(cfg, log, metadata=metadata)
    else:
        notifier = TelegramNotifier(cfg, log, metadata=metadata)

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
    if not notifier.send(external):
        print(f"Heartbeat stale ({detail}); failed to send alert.", file=sys.stderr)
        return 1
    state.mark_alert_sent(_HEARTBEAT_FINGERPRINT, cfg.alert_cooldown_seconds)
    print(f"Heartbeat stale ({detail}); alert sent.")
    return 0


class Agent:
    def __init__(self, cfg: Config):
        cfg.validate()
        self.cfg = cfg
        self.log = setup_logging(cfg.log_file, cfg.log_level)

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
        self.tailer = FileTailer(self.state, self.log)
        self.evidence_collector = (
            EvidenceCollector(max_lines=getattr(cfg, "evidence_lines", 15), logger=self.log)
            if getattr(cfg, "collect_incident_evidence", True)
            else None
        )

        self.health = HealthMonitor(cfg, self.state, self.log)
        self.web = WebLogMonitor(cfg, self.tailer, self.log)
        self.ssh = SSHMonitor(cfg, self.state, self.tailer, self.log)
        self.kernel = KernelMonitor(cfg, self.state, self.tailer, self.log)

        self.ai = AIAnalyzer(cfg, self.log, metadata=self.metadata)
        self.notifier = (
            EmailNotifier(cfg, self.log, metadata=self.metadata)
            if cfg.alert_channel == "email"
            else TelegramNotifier(cfg, self.log, metadata=self.metadata)
        )
        self.running = True

        # Alerts (evidence collection, AI triage, delivery) may block on network
        # I/O. Process them on a single background worker so monitoring cycles
        # are never stalled. A single worker keeps shared state free of races.
        self._alert_queue: "queue.Queue[object]" = queue.Queue(maxsize=1000)
        self._alert_stop = object()
        self._alert_worker = threading.Thread(
            target=self._alert_worker_loop,
            name="alert-worker",
            daemon=True,
        )
        self._alert_worker.start()

    def stop(self, *_):
        self.running = False

    def dispatch(self, incident):
        """Queue an incident for asynchronous processing."""
        try:
            self._alert_queue.put_nowait(incident)
        except queue.Full:
            self.log.warning(
                "Alert queue full; dropping incident: %s", incident.fingerprint
            )

    def _alert_worker_loop(self):
        while True:
            item = self._alert_queue.get()
            try:
                if item is self._alert_stop:
                    return
                self._process(item)
            except Exception:
                self.log.exception("Alert dispatch error")
            finally:
                self._alert_queue.task_done()

    def _process(self, incident):
        # Security logins are intentionally unique per user/IP but still cooldown-protected.
        if not self.state.can_alert(
            incident.fingerprint, self.cfg.alert_cooldown_seconds
        ):
            self.log.info("Suppressed duplicate alert: %s", incident.fingerprint)
            return

        # Collect real-time diagnostic evidence logs before notifying or asking AI
        if self.evidence_collector and not getattr(incident, "evidence", ""):
            incident.evidence = self.evidence_collector.collect(incident)

        # Source logs remain local. Only this safe copy can leave the server.
        external_incident = sanitize_incident(incident)

        # AI is enrichment only; alerting never depends on it.
        if incident.severity in {"WARNING", "CRITICAL"}:
            external_incident.ai_analysis = self.ai.analyze(external_incident)
            external_incident = sanitize_incident(external_incident)

        # A failed delivery must not suppress the next alert.
        if self.notifier.send(external_incident):
            self.state.mark_alert_sent(
                incident.fingerprint, self.cfg.alert_cooldown_seconds
            )

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

    def run_once(self):
        try:
            self.state.set_heartbeat()
        except Exception:
            self.log.exception("Failed to update heartbeat")
        for incident in self.health.collect():
            self.dispatch(incident)
        for incident in self.web.collect():
            self.dispatch(incident)
        for incident in self.ssh.collect():
            self.dispatch(incident)
        for incident in self.kernel.collect():
            self.dispatch(incident)
        self.drain()

    def run(self):
        badge = f" [{self.metadata.badge()}]" if self.metadata else ""
        self.log.info(
            "Server AI Agent started server=%s env=%s%s",
            self.cfg.server_name,
            self.cfg.environment,
            badge,
        )
        last_health = 0.0
        last_logs = 0.0
        try:
            self.state.set_heartbeat()
        except Exception:
            self.log.exception("Failed to update heartbeat")
        last_heartbeat = time.monotonic()

        while self.running:
            now = time.monotonic()
            if now - last_heartbeat >= _HEARTBEAT_WRITE_SECONDS:
                try:
                    self.state.set_heartbeat()
                    last_heartbeat = now
                except Exception:
                    self.log.exception("Failed to update heartbeat")
            try:
                if now - last_health >= self.cfg.health_interval:
                    for incident in self.health.collect():
                        self.dispatch(incident)
                    last_health = now

                if now - last_logs >= self.cfg.log_interval:
                    for incident in self.web.collect():
                        self.dispatch(incident)
                    for incident in self.ssh.collect():
                        self.dispatch(incident)
                    for incident in self.kernel.collect():
                        self.dispatch(incident)
                    last_logs = now
            except Exception:
                self.log.exception("Unhandled monitor-cycle error")

            time.sleep(1)

        self._shutdown_worker()
        self.log.info("Server AI Agent stopped")


def main():
    parser = argparse.ArgumentParser(description="Read-only AI server health/security monitor")
    parser.add_argument("--once", action="store_true", help="Run one monitoring cycle and exit")
    parser.add_argument("--test-notification", action="store_true", help="Send a test alert through the selected channel and exit")
    parser.add_argument("--test-email", action="store_true", help="Deprecated alias for --test-notification when email is selected")
    parser.add_argument("--check-config", action="store_true", help="Validate config and exit")
    parser.add_argument("--check-heartbeat", action="store_true", help="Run the heartbeat watchdog and exit")
    args = parser.parse_args()

    try:
        cfg = Config()
        cfg.validate()
    except Exception as exc:
        print(f"Configuration/startup error: {exc}", file=sys.stderr)
        return 2

    if args.check_config:
        print("Configuration OK")
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
        return 0 if agent.notifier.send_test() else 1
    if args.once:
        agent.run_once()
        return 0

    signal.signal(signal.SIGTERM, agent.stop)
    signal.signal(signal.SIGINT, agent.stop)
    agent.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
