from types import SimpleNamespace

from server_agent.monitors import kernel as kernel_module
from server_agent.monitors.kernel import KernelMonitor


class FakeTailer:
    def __init__(self, lines_by_path):
        self.lines_by_path = lines_by_path
        self.calls = []

    def read_new_lines(self, path, max_lines, max_line_chars):
        self.calls.append((path, max_lines, max_line_chars))
        return list(self.lines_by_path.get(path, []))


class FakeState:
    def __init__(self, cursor=None):
        self.cursor = cursor
        self.updated = []

    def journal_cursor(self, key="kernel"):
        return self.cursor

    def update_journal_cursor(self, key, cursor):
        self.updated.append((key, cursor))


class FakeLogger:
    def __init__(self):
        self.messages = []

    def debug(self, message, *args):
        self.messages.append(message % args if args else message)


def _config(logs=None, enabled=True, fallback=True, max_lines=7):
    return SimpleNamespace(
        resolved_kernel_logs=lambda: list(logs or []),
        kernel_monitor_enabled=enabled,
        kernel_journal_fallback=fallback,
        max_log_lines_per_cycle=max_lines,
        max_log_line_chars=4096,
        max_log_sample_chars=600,
    )


def _monitor(logs=None, state=None, tailer=None, **kwargs):
    return KernelMonitor(
        _config(logs, **kwargs),
        state or FakeState(),
        tailer or FakeTailer({}),
        FakeLogger(),
    )


def test_read_from_files_only_existing_paths(monkeypatch):
    monkeypatch.setattr(
        kernel_module,
        "safe_path_exists",
        lambda path: path == "/var/log/kern.log",
    )
    tailer = FakeTailer({"/var/log/kern.log": ["first", "second"]})
    monitor = _monitor(
        ["/var/log/kern.log", "/missing.log"], tailer=tailer
    )

    records = monitor._read_from_files()

    assert records == [
        ("/var/log/kern.log", "first"),
        ("/var/log/kern.log", "second"),
    ]
    assert tailer.calls == [("/var/log/kern.log", 7, 4096)]


def test_read_from_journal_first_run_uses_n_zero(monkeypatch):
    state = FakeState(cursor=None)
    stdout = "\n".join(
        [
            "-- Logs begin at Mon 2026-01-01 00:00:00 UTC.",
            "2026-01-01T00:00:01+0000 host kernel: oom_reaper: reaped process 9 (php-fpm)",
            "-- cursor: s=abc;i=1",
        ]
    )
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout=stdout)

    monkeypatch.setattr(kernel_module.subprocess, "run", fake_run)
    monitor = _monitor(state=state)

    records = monitor._read_from_journal()

    assert calls[0][:4] == ["journalctl", "-k", "--show-cursor", "-o"]
    assert "--after-cursor" not in calls[0]
    assert calls[0][calls[0].index("-n") + 1] == "0"
    assert records == [
        (
            "journalctl -k",
            "2026-01-01T00:00:01+0000 host kernel: oom_reaper: reaped process 9 (php-fpm)",
        )
    ]
    assert state.updated == [("kernel", "s=abc;i=1")]


def test_read_from_journal_uses_saved_cursor(monkeypatch):
    state = FakeState(cursor="s=1;i=2")
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(kernel_module.subprocess, "run", fake_run)
    monitor = _monitor(state=state, max_lines=7)

    assert monitor._read_from_journal() == []
    cmd = calls[0]
    assert cmd[cmd.index("--after-cursor") + 1] == "s=1;i=2"
    assert cmd[cmd.index("-n") + 1] == "7"
    assert state.updated == []


def test_read_from_journal_nonzero_exit_returns_empty(monkeypatch):
    monkeypatch.setattr(
        kernel_module.subprocess,
        "run",
        lambda cmd, **kwargs: SimpleNamespace(returncode=1, stdout="ignored"),
    )
    monitor = _monitor()

    assert monitor._read_from_journal() == []


def test_read_from_journal_missing_binary_is_swallowed(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("journalctl")

    monkeypatch.setattr(kernel_module.subprocess, "run", fake_run)
    monitor = _monitor()

    assert monitor._read_from_journal() == []
    assert "Journalctl kernel inspection skipped" in monitor.logger.messages[0]


def test_collect_disabled_returns_empty(monkeypatch):
    monitor = _monitor(enabled=False)
    monkeypatch.setattr(
        monitor,
        "_read_from_files",
        lambda: (_ for _ in ()).throw(AssertionError("should not read")),
    )

    assert monitor.collect() == []


def test_collect_falls_back_to_journal_when_no_files_exist(monkeypatch):
    monkeypatch.setattr(kernel_module, "safe_path_exists", lambda path: False)
    monitor = _monitor(["/var/log/kern.log"])
    monkeypatch.setattr(monitor, "_read_from_files", lambda: [])
    monkeypatch.setattr(
        monitor,
        "_read_from_journal",
        lambda: [("journalctl -k", "Kernel panic - not syncing: fatal")],
    )

    incidents = monitor.collect()

    assert len(incidents) == 1
    assert incidents[0].kind == "kernel_crash"
    assert incidents[0].severity == "CRITICAL"


def test_collect_does_not_fallback_when_file_exists(monkeypatch):
    monkeypatch.setattr(kernel_module, "safe_path_exists", lambda path: True)
    monitor = _monitor(["/var/log/kern.log"])
    monkeypatch.setattr(monitor, "_read_from_files", lambda: [])
    monkeypatch.setattr(
        monitor,
        "_read_from_journal",
        lambda: (_ for _ in ()).throw(AssertionError("unexpected fallback")),
    )

    assert monitor.collect() == []


def test_collect_dedupes_identical_oom_lines_in_one_batch(monkeypatch):
    monitor = _monitor()
    monkeypatch.setattr(
        monitor,
        "_read_from_files",
        lambda: [
            ("/var/log/kern.log", "Killed process 42 (nginx) total-vm:1234kB"),
            ("/var/log/kern.log", "Killed process 42 (nginx) total-vm:1234kB"),
        ],
    )

    incidents = monitor.collect()

    assert len(incidents) == 1
    assert incidents[0].fingerprint == "oom:nginx"
    assert incidents[0].details["process"] == "nginx"
    assert incidents[0].details["pid"] == "42"


def test_collect_parses_reaper_line_from_file(monkeypatch):
    monitor = _monitor()
    monkeypatch.setattr(
        monitor,
        "_read_from_files",
        lambda: [
            (
                "/var/log/kern.log",
                "oom_reaper: reaped process 7 (php-fpm), now anon-rss:0kB",
            )
        ],
    )

    incidents = monitor.collect()

    assert len(incidents) == 1
    assert incidents[0].details["process"] == "php-fpm"
    assert incidents[0].details["source"] == "/var/log/kern.log"
