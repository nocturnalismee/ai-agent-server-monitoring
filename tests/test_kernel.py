import logging
from types import SimpleNamespace

from server_agent.monitors.kernel import KernelMonitor


def _create_monitor():
    cfg = SimpleNamespace(
        kernel_monitor_enabled=True,
        max_log_sample_chars=600,
        max_log_lines_per_cycle=250,
        max_log_line_chars=4096,
        resolved_kernel_logs=lambda: [],
        kernel_journal_fallback=False,
    )
    logger = logging.getLogger("test")
    return KernelMonitor(cfg, state=None, tailer=None, logger=logger)


def test_parse_oom_killer_debian_ubuntu_format():
    monitor = _create_monitor()
    line = (
        "Oct 23 09:00:00 server kernel: [12345.678] "
        "Out of memory: Killed process 1234 (mysqld) total-vm:2097152kB, anon-rss:1048576kB, file-rss:0kB"
    )
    seen = set()
    incident = monitor._parse_line(line, "/var/log/kern.log", seen)
    assert incident is not None
    assert incident.kind == "oom"
    assert incident.severity == "CRITICAL"
    assert incident.fingerprint == "oom:mysqld"
    assert incident.details["process"] == "mysqld"
    assert incident.details["pid"] == "1234"
    assert "mysqld" in incident.title


def test_parse_cgroup_oom_killer():
    monitor = _create_monitor()
    line = (
        "Oct 23 09:00:01 server kernel: [12345.679] "
        "Memory cgroup out of memory: Killed process 5678 (php-fpm) total-vm:524288kB"
    )
    seen = set()
    incident = monitor._parse_line(line, "/var/log/messages", seen)
    assert incident is not None
    assert incident.kind == "oom"
    assert incident.severity == "CRITICAL"
    assert incident.details["process"] == "php-fpm"
    assert incident.details["pid"] == "5678"


def test_parse_oom_reaper():
    monitor = _create_monitor()
    line = "Oct 23 09:00:02 server kernel: [12345.680] oom_reaper: reaped process 9999 (node), now anon-rss:0kB"
    seen = set()
    incident = monitor._parse_line(line, "/var/log/kern.log", seen)
    assert incident is not None
    assert incident.kind == "oom"
    assert incident.details["process"] == "node"
    assert incident.details["pid"] == "9999"


def test_parse_generic_oom_invoked():
    monitor = _create_monitor()
    line = "Oct 23 09:00:03 server kernel: [12345.681] node invoked oom-killer: gfp_mask=0x1100cca"
    seen = set()
    incident = monitor._parse_line(line, "/var/log/kern.log", seen)
    assert incident is not None
    assert incident.kind == "oom"
    assert incident.fingerprint == "oom:invoked"


def test_deduplicates_same_process_in_single_batch():
    monitor = _create_monitor()
    line1 = "Out of memory: Killed process 1234 (mysqld) total-vm:2097152kB"
    line2 = "oom_reaper: reaped process 1234 (mysqld), now anon-rss:0kB"
    seen = set()

    incident1 = monitor._parse_line(line1, "/var/log/kern.log", seen)
    incident2 = monitor._parse_line(line2, "/var/log/kern.log", seen)

    assert incident1 is not None
    assert incident2 is None
    assert len(seen) == 1


def test_parse_kernel_crash_panic():
    monitor = _create_monitor()
    cases = [
        ("Kernel panic - not syncing: Fatal exception", "Kernel panic - not syncing"),
        ("kernel: BUG: unable to handle kernel NULL pointer dereference", "BUG: unable to handle kernel"),
        ("general protection fault: 0000 [#1] SMP", "general protection fault"),
    ]
    for line, expected_type in cases:
        seen = set()
        incident = monitor._parse_line(line, "/var/log/kern.log", seen)
        assert incident is not None
        assert incident.kind == "kernel_crash"
        assert incident.severity == "CRITICAL"
        assert incident.details["error_type"] == expected_type


def test_ignores_normal_kernel_lines():
    monitor = _create_monitor()
    normal_lines = [
        "Linux version 6.5.0-generic (buildd@lcy02-amd64-072)",
        "systemd[1]: Started User Manager for UID 1000.",
        "ACPI: PCI Root Bridge [PCI0] (domain 0000 [bus 00-ff])",
    ]
    for line in normal_lines:
        assert monitor._parse_line(line, "/var/log/kern.log", set()) is None
