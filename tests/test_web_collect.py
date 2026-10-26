from types import SimpleNamespace

from server_agent.monitors import web as web_module
from server_agent.monitors.web import WebLogMonitor


class FakeTailer:
    def __init__(self, lines_by_path):
        self.lines_by_path = lines_by_path
        self.calls = []

    def read_new_lines(self, path, max_lines, max_line_chars):
        self.calls.append((path, max_lines, max_line_chars))
        return list(self.lines_by_path.get(path, []))


class FakeLogger:
    def debug(self, *args, **kwargs):
        pass


def _config(logs, threshold=1, sample_chars=600):
    return SimpleNamespace(
        resolved_web_error_logs=lambda: list(logs),
        web_error_batch_threshold=threshold,
        max_log_sample_chars=sample_chars,
        max_log_lines_per_cycle=250,
        max_log_line_chars=4096,
    )


def _monitor(logs, lines_by_path, threshold=1, sample_chars=600):
    return WebLogMonitor(
        _config(logs, threshold, sample_chars),
        FakeTailer(lines_by_path),
        FakeLogger(),
    )


def test_collect_skips_missing_and_dedupes_paths(monkeypatch):
    existing = {"/var/log/nginx/error.log"}
    monkeypatch.setattr(
        web_module, "safe_path_exists", lambda path: path in existing
    )
    path = "/var/log/nginx/error.log"
    monitor = _monitor(
        [path, path, "/missing.log"],
        {path: ["upstream timed out while reading response header"]},
    )

    incidents = monitor.collect()

    assert len(incidents) == 1
    assert monitor.tailer.calls == [(path, 250, 4096)]
    assert incidents[0].details["server"] == "Nginx"
    assert incidents[0].details["log_path"] == path


def test_collect_returns_no_incident_below_threshold(monkeypatch):
    monkeypatch.setattr(web_module, "safe_path_exists", lambda path: True)
    path = "/var/log/nginx/error.log"
    monitor = _monitor([path], {path: ["upstream timed out"]}, threshold=5)

    assert monitor.collect() == []


def _analyze(lines, threshold=1):
    monitor = _monitor([], {}, threshold=threshold)
    return monitor._analyze("Nginx", "/var/log/nginx/error.log", lines)


def test_analyze_empty_lines_returns_none():
    assert _analyze([]) is None
    assert _analyze(["   "]) is None


def test_analyze_resource_pressure_is_critical():
    incident = _analyze(["worker_connections are not enough"])

    assert incident is not None
    assert incident.severity == "CRITICAL"
    assert incident.details["categories"]["resource pressure"] == 1


def test_analyze_five_connection_refused_is_critical():
    lines = ["connect() failed (111: Connection refused)"] * 5
    incident = _analyze(lines)

    assert incident is not None
    assert incident.severity == "CRITICAL"
    assert incident.details["categories"]["connection refused"] == 5


def test_analyze_fifty_entries_is_critical():
    incident = _analyze(["unremarkable notice"] * 50)

    assert incident is not None
    assert incident.severity == "CRITICAL"
    assert incident.details["categories"]["other"] == 50


def test_analyze_single_error_is_warning_and_has_stable_fingerprint():
    incident = _analyze(["upstream timed out (110: Connection timed out)"])

    assert incident is not None
    assert incident.severity == "WARNING"
    assert incident.fingerprint == "web:Nginx:upstream timeout"
    assert incident.summary.startswith("1 new Nginx error-log entries")


def test_analyze_unclassified_lines_are_grouped_as_other():
    incident = _analyze(["something odd happened"])

    assert incident is not None
    assert incident.details["categories"] == {"other": 1}
    assert "other=1" in incident.summary


def test_analyze_samples_are_bounded_and_keep_the_tail():
    lines = [f"upstream timed out {i} " + "x" * 200 for i in range(12)]
    incident = _analyze(lines, threshold=1)

    assert incident is not None
    samples = incident.details["samples"]
    assert len(samples) == 8
    assert all(len(sample) <= 600 for sample in samples)
    assert "upstream timed out 11" in samples[-1]
