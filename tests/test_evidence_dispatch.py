import subprocess
from types import SimpleNamespace

from server_agent.collectors import evidence as evidence_module
from server_agent.collectors.evidence import EvidenceCollector
from server_agent.core.models import Incident


class FakeLogger:
    def __init__(self):
        self.debugs = []

    def debug(self, message, *args):
        self.debugs.append(message % args)


def _incident(kind, *, metric=None, service=None, title="incident"):
    details = {}
    if metric is not None:
        details["metric"] = metric
    if service is not None:
        details["service"] = service
    return Incident(
        kind=kind,
        severity="WARNING",
        title=title,
        summary="",
        fingerprint="fp:test",
        details=details,
    )


def _completed(stdout="", stderr=""):
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=0)


def test_dispatch_service_uses_journal(monkeypatch):
    collector = EvidenceCollector()
    captured = {}

    def fake_journal(service):
        captured["service"] = service
        return "svc evidence"

    monkeypatch.setattr(collector, "_collect_service_journal", fake_journal)
    assert collector.collect(_incident("service", service="nginx")) == "svc evidence"
    assert captured["service"] == "nginx"


def test_dispatch_service_without_name_returns_empty(monkeypatch):
    collector = EvidenceCollector()

    def boom(service):
        raise AssertionError("must not collect without a service name")

    monkeypatch.setattr(collector, "_collect_service_journal", boom)
    assert collector.collect(_incident("service")) == ""


def test_dispatch_cpu_and_load_use_top_cpu(monkeypatch):
    collector = EvidenceCollector()
    monkeypatch.setattr(collector, "_collect_top_cpu_processes", lambda: "cpu")
    monkeypatch.setattr(collector, "_collect_top_memory_processes", lambda: "mem")
    assert collector.collect(_incident("health", metric="CPU")) == "cpu"
    assert collector.collect(_incident("health", metric="Load-per-CPU")) == "cpu"


def test_dispatch_memory_uses_top_memory(monkeypatch):
    collector = EvidenceCollector()
    monkeypatch.setattr(collector, "_collect_top_memory_processes", lambda: "mem")
    assert collector.collect(_incident("health", metric="Memory")) == "mem"


def test_dispatch_disk_uses_overview(monkeypatch):
    collector = EvidenceCollector()
    captured = {}

    def fake_overview(mount):
        captured["mount"] = mount
        return "df"

    monkeypatch.setattr(collector, "_collect_disk_overview", fake_overview)
    assert collector.collect(_incident("health", metric="Disk /var")) == "df"
    assert captured["mount"] == "/var"


def test_dispatch_unknown_kind_returns_empty():
    assert EvidenceCollector().collect(_incident("ssh_login")) == ""


def test_dispatch_swallows_errors_and_logs_debug():
    logger = FakeLogger()
    collector = EvidenceCollector(logger=logger)

    def boom(service):
        raise RuntimeError("kaboom")

    collector._collect_service_journal = boom
    assert collector.collect(_incident("service", service="nginx")) == ""
    assert logger.debugs and "kaboom" in logger.debugs[0]


def test_service_journal_formats_output(monkeypatch):
    monkeypatch.setattr(
        evidence_module.subprocess,
        "run",
        lambda *a, **k: _completed("line one\nline two\n"),
    )
    text = EvidenceCollector(max_lines=7)._collect_service_journal("nginx")
    assert text.startswith("--- journalctl -u nginx (last 7 lines) ---")
    assert "line one" in text


def test_service_journal_empty_output_returns_empty(monkeypatch):
    monkeypatch.setattr(evidence_module.subprocess, "run", lambda *a, **k: _completed("  \n"))
    assert EvidenceCollector()._collect_service_journal("nginx") == ""


def test_service_journal_missing_binary_returns_empty(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("journalctl")

    monkeypatch.setattr(evidence_module.subprocess, "run", missing)
    assert EvidenceCollector()._collect_service_journal("nginx") == ""


def test_service_status_uses_stderr_when_stdout_empty(monkeypatch):
    def fake_run(command, **kwargs):
        if command[0] == "journalctl":
            return _completed("")
        return _completed("", "Unit nginx.service could not be found.\n")

    monkeypatch.setattr(evidence_module.subprocess, "run", fake_run)
    text = EvidenceCollector()._collect_service_journal("nginx")
    assert "--- systemctl status nginx ---" in text
    assert "could not be found" in text


def test_service_status_concatenates_stdout_and_stderr(monkeypatch):
    def fake_run(command, **kwargs):
        if command[0] == "journalctl":
            return _completed("")
        return _completed("stdout-line\n", "stderr-line\n")

    monkeypatch.setattr(evidence_module.subprocess, "run", fake_run)
    text = EvidenceCollector()._collect_service_journal("nginx")
    assert "stdout-line" in text
    assert "stderr-line" in text


def test_service_status_keeps_first_max_lines_of_combined_output(monkeypatch):
    def fake_run(command, **kwargs):
        if command[0] == "journalctl":
            return _completed("")
        return _completed("out-1\nout-2\n", "err-1\nerr-2\n")

    monkeypatch.setattr(evidence_module.subprocess, "run", fake_run)
    text = EvidenceCollector(max_lines=3)._collect_service_journal("nginx")
    assert "out-1" in text
    assert "out-2" in text
    assert "err-1" in text
    assert "err-2" not in text


def test_top_cpu_limits_to_six_lines(monkeypatch):
    output = "header\n" + "\n".join(f"proc{i}" for i in range(10))
    monkeypatch.setattr(evidence_module.subprocess, "run", lambda *a, **k: _completed(output))
    text = EvidenceCollector()._collect_top_cpu_processes()
    assert text.startswith("--- Top 5 CPU Processes ---")
    assert "proc4" in text
    assert "proc5" not in text


def test_top_memory_formats_output(monkeypatch):
    monkeypatch.setattr(
        evidence_module.subprocess,
        "run",
        lambda *a, **k: _completed("header\nproc"),
    )
    text = EvidenceCollector()._collect_top_memory_processes()
    assert text.startswith("--- Top 5 Memory Processes ---")
    assert text.endswith("proc")


def test_top_cpu_error_returns_empty(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("ps")

    monkeypatch.setattr(evidence_module.subprocess, "run", missing)
    assert EvidenceCollector()._collect_top_cpu_processes() == ""


def test_disk_overview_uses_mount_and_formats(monkeypatch):
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        return _completed("Filesystem Size Used\n/dev/sda1 10G 5G")

    monkeypatch.setattr(evidence_module.subprocess, "run", fake_run)
    text = EvidenceCollector()._collect_disk_overview("/var")
    assert captured["args"] == ["df", "-h", "--", "/var"]
    assert text.startswith("--- df -h /var ---")


def test_disk_overview_rejects_unsafe_target(monkeypatch):
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        return _completed("ok")

    monkeypatch.setattr(evidence_module.subprocess, "run", fake_run)
    EvidenceCollector()._collect_disk_overview("; rm -rf /")
    assert captured["args"][-1] == "/"


def test_disk_overview_relative_mount_defaults_to_root(monkeypatch):
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        return _completed("ok")

    monkeypatch.setattr(evidence_module.subprocess, "run", fake_run)
    EvidenceCollector()._collect_disk_overview("tmp")
    assert captured["args"][-1] == "/"


def test_disk_overview_error_returns_empty(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("df")

    monkeypatch.setattr(evidence_module.subprocess, "run", missing)
    assert EvidenceCollector()._collect_disk_overview("/") == ""


def test_service_evidence_uses_resolved_unit(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "line-1\nline-2\n", "")

    monkeypatch.setattr(evidence_module.subprocess, "run", fake_run)
    collector = EvidenceCollector(max_lines=10)
    incident = Incident(
        kind="service",
        severity="CRITICAL",
        title="Service mysql is not active",
        summary="",
        fingerprint="service:mysql",
        details={"service": "mysql", "unit": "mariadb.service"},
    )
    text = collector.collect(incident)
    assert calls[0][:3] == ["journalctl", "-u", "mariadb.service"]
    assert calls[1][:2] == ["systemctl", "status"]
    assert "mariadb.service" in text
    assert "systemctl status mariadb.service" in text


def test_service_evidence_rejects_unsafe_unit(monkeypatch):
    calls = []
    monkeypatch.setattr(
        evidence_module.subprocess,
        "run",
        lambda command, **kwargs: calls.append(command),
    )
    collector = EvidenceCollector()
    incident = Incident(
        kind="service",
        severity="CRITICAL",
        title="bad",
        summary="",
        fingerprint="service:bad",
        details={"service": "mysql", "unit": "mysql; rm -rf /"},
    )
    assert collector.collect(incident) == ""
    assert calls == []


def test_service_evidence_rejects_unit_with_trailing_newline(monkeypatch):
    calls = []
    monkeypatch.setattr(
        evidence_module.subprocess,
        "run",
        lambda command, **kwargs: calls.append(command),
    )
    collector = EvidenceCollector()
    incident = Incident(
        kind="service",
        severity="CRITICAL",
        title="bad",
        summary="",
        fingerprint="service:bad",
        details={"service": "mysql", "unit": "mysql\n"},
    )
    assert collector.collect(incident) == ""
    assert calls == []


def test_service_evidence_falls_back_to_service_name(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "ok\n", "")

    monkeypatch.setattr(evidence_module.subprocess, "run", fake_run)
    collector = EvidenceCollector()
    incident = Incident(
        kind="service",
        severity="CRITICAL",
        title="Service nginx is not active",
        summary="",
        fingerprint="service:nginx",
        details={"service": "nginx"},
    )
    text = collector.collect(incident)
    assert calls[0][:3] == ["journalctl", "-u", "nginx"]
    assert "nginx" in text
