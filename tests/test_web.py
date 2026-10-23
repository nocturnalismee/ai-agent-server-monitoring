from types import SimpleNamespace

from server_agent.monitors.web import WebLogMonitor


def _monitor(sample_chars=100):
    return WebLogMonitor(
        SimpleNamespace(web_error_batch_threshold=1, max_log_sample_chars=sample_chars),
        tailer=None,
        logger=SimpleNamespace(),
    )


def test_panel_log_labels_are_explicit():
    monitor = _monitor()
    assert monitor._server_name("/usr/local/lsws/logs/error.log") == "LiteSpeed"
    assert monitor._server_name("/var/log/directadmin/error.log") == "DirectAdmin"
    assert monitor._server_name("/var/log/sw-cp-server/error_log") == "Plesk"


def test_web_samples_are_bounded_without_losing_error_category():
    monitor = _monitor(sample_chars=100)
    incident = monitor._analyze(
        "LiteSpeed",
        "/usr/local/lsws/logs/error.log",
        ["[ERROR] lsapi failure " + "x" * 200],
    )
    assert incident is not None
    assert incident.details["categories"]["litespeed"] == 1
    assert len(incident.details["samples"][0]) <= 100
    assert incident.details["samples"][0].endswith("[truncated]")
