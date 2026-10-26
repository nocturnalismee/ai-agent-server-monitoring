from types import SimpleNamespace

from server_agent.monitors import ssh as ssh_module
from server_agent.monitors.ssh import SSHMonitor


class FakeState:
    def __init__(self):
        self.failures = {}
        self.cleared = []

    def add_ssh_failure(self, ip, timestamp, window):
        self.failures[ip] = self.failures.get(ip, 0) + 1
        return self.failures[ip]

    def clear_ssh_failures(self, ip):
        self.cleared.append(ip)
        self.failures.pop(ip, None)


class FakeTailer:
    def __init__(self, lines):
        self.lines = lines
        self.calls = []

    def read_new_lines(self, path, max_lines, max_line_chars):
        self.calls.append((path, max_lines, max_line_chars))
        return self.lines


class FakeLogger:
    def __init__(self):
        self.warnings = []

    def warning(self, message, *args):
        self.warnings.append(message % args)


def make_config(**overrides):
    base = {
        "trusted_ssh_networks": ["10.0.0.0/8"],
        "auth_log": "/var/log/auth.log",
        "auth_log_rhel": "",
        "max_log_sample_chars": 100,
        "max_log_lines_per_cycle": 250,
        "max_log_line_chars": 4096,
        "ssh_alert_success": True,
        "ssh_alert_root_login": True,
        "ssh_alert_failed_burst": True,
        "ssh_failed_threshold": 3,
        "ssh_failed_window_seconds": 300,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def make_monitor(lines, **overrides):
    tailer = FakeTailer(lines)
    monitor = SSHMonitor(make_config(**overrides), FakeState(), tailer, logger=None)
    monitor._auth_paths = lambda: ["/var/log/auth.log"]
    return monitor


def test_trusted_login_is_info_and_clears_failures():
    monitor = make_monitor(
        ["Accepted publickey for deploy from 10.1.2.3 port 2222 ssh2"]
    )
    incidents = monitor.collect()
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.kind == "ssh_login"
    assert incident.severity == "INFO"
    assert incident.details["trusted_network"] is True
    assert incident.fingerprint == "ssh:success:deploy:10.1.2.3"
    assert monitor.state.cleared == ["10.1.2.3"]


def test_untrusted_login_is_warning():
    monitor = make_monitor(
        ["Accepted password for alice from 198.51.100.7 port 4444 ssh2"]
    )
    incidents = monitor.collect()
    assert len(incidents) == 1
    assert incidents[0].severity == "WARNING"
    assert incidents[0].details["trusted_network"] is False


def test_root_login_is_critical_when_enabled():
    monitor = make_monitor(
        ["Accepted password for root from 198.51.100.7 port 4444 ssh2"]
    )
    incidents = monitor.collect()
    assert len(incidents) == 1
    assert incidents[0].severity == "CRITICAL"


def test_root_login_flag_disabled_downgrades_severity():
    monitor = make_monitor(
        ["Accepted password for root from 198.51.100.7 port 4444 ssh2"],
        ssh_alert_root_login=False,
    )
    incidents = monitor.collect()
    assert len(incidents) == 1
    assert incidents[0].severity == "WARNING"


def test_success_alert_disabled_still_clears_failures():
    monitor = make_monitor(
        ["Accepted publickey for deploy from 10.1.2.3 port 2222 ssh2"],
        ssh_alert_success=False,
    )
    assert monitor.collect() == []
    assert monitor.state.cleared == ["10.1.2.3"]


def test_failed_login_burst_emits_one_incident_at_threshold():
    monitor = make_monitor(
        [
            "Failed password for invalid user admin from 198.51.100.7 port 1 ssh2",
            "Failed password for invalid user admin from 198.51.100.7 port 2 ssh2",
            "Failed password for invalid user admin from 198.51.100.7 port 3 ssh2",
        ]
    )
    incidents = monitor.collect()
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.kind == "ssh_bruteforce"
    assert incident.severity == "CRITICAL"
    assert incident.fingerprint == "ssh:failed-burst:198.51.100.7"
    assert incident.details["attempts_in_window"] == 3
    assert incident.details["last_user"] == "admin"


def test_failed_burst_disabled_records_but_does_not_alert():
    monitor = make_monitor(
        ["Failed password for root from 198.51.100.7 port 1 ssh2"],
        ssh_alert_failed_burst=False,
    )
    assert monitor.collect() == []
    assert monitor.state.failures["198.51.100.7"] == 1


def test_invalid_trusted_network_is_ignored_with_warning():
    logger = FakeLogger()
    monitor = SSHMonitor(
        make_config(trusted_ssh_networks=["not-a-cidr", "10.0.0.0/8"]),
        FakeState(),
        FakeTailer([]),
        logger,
    )
    assert len(monitor.trusted) == 1
    assert "not-a-cidr" in logger.warnings[0]
    assert monitor._is_trusted("10.1.1.1") is True
    assert monitor._is_trusted("203.0.113.5") is False
    assert monitor._is_trusted("garbage") is False


def test_sample_truncates_long_lines():
    monitor = make_monitor([], max_log_sample_chars=40)
    sample = monitor._sample("x" * 100)
    assert len(sample) <= 40
    assert sample.endswith("[truncated]")


def test_auth_paths_deduplicates_and_skips_missing(monkeypatch):
    monkeypatch.setattr(ssh_module, "safe_path_exists", lambda path: path != "/missing")
    monitor = SSHMonitor(
        make_config(auth_log="/var/log/auth.log", auth_log_rhel="/var/log/auth.log"),
        FakeState(),
        FakeTailer([]),
        logger=None,
    )
    assert monitor._auth_paths() == ["/var/log/auth.log"]
