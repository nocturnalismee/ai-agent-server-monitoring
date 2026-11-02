from types import SimpleNamespace

import pytest

from server_agent.collectors import evidence as evidence_module
from server_agent.collectors.evidence import EvidenceCollector
from server_agent.core.models import Incident


def _health_incident(title, metric):
    return Incident(
        kind="health",
        severity="WARNING",
        title=title,
        summary="",
        fingerprint="health:test",
        details={"metric": metric},
    )


def test_disk_evidence_uses_structured_metric(monkeypatch):
    collector = EvidenceCollector()
    captured = {}

    def fake_overview(mount):
        captured["mount"] = mount
        return "df output"

    monkeypatch.setattr(collector, "_collect_disk_overview", fake_overview)
    result = collector.collect(
        _health_incident("Disk /var threshold exceeded", "Disk /var")
    )
    assert result == "df output"
    assert captured["mount"] == "/var"


def test_disk_evidence_falls_back_to_title(monkeypatch):
    collector = EvidenceCollector()
    captured = {}

    def fake_overview(mount):
        captured["mount"] = mount
        return "df output"

    monkeypatch.setattr(collector, "_collect_disk_overview", fake_overview)
    collector.collect(
        _health_incident("Disk /srv threshold exceeded", "Disk")
    )
    assert captured["mount"] == "/srv"


def test_service_evidence_rejects_untrusted_names(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("subprocess must not run for invalid service names")

    monkeypatch.setattr(evidence_module.subprocess, "run", boom)
    collector = EvidenceCollector()
    incident = Incident(
        kind="service",
        severity="CRITICAL",
        title="Service down",
        summary="",
        fingerprint="service:test",
        details={"service": "nginx; rm -rf /"},
    )
    assert collector.collect(incident) == ""


def _proc(stdout="", stderr=""):
    return SimpleNamespace(stdout=stdout, stderr=stderr)


def _assert_line_cap(text):
    assert "[truncated]" in text
    assert all(len(line) <= 2000 for line in text.splitlines())


@pytest.mark.parametrize(
    "method", ["_collect_top_cpu_processes", "_collect_top_memory_processes"]
)
def test_ps_evidence_caps_each_line(monkeypatch, method):
    long_line = "p" * 5000
    monkeypatch.setattr(
        evidence_module.subprocess, "run", lambda *a, **k: _proc(long_line + "\n")
    )

    result = getattr(EvidenceCollector(), method)()

    _assert_line_cap(result)


def test_df_evidence_caps_each_line(monkeypatch):
    monkeypatch.setattr(
        evidence_module.subprocess,
        "run",
        lambda *a, **k: _proc("Filesystem Size Used Avail Use%\n" + "d" * 5000),
    )

    result = EvidenceCollector()._collect_disk_overview("/")

    _assert_line_cap(result)


def test_journalctl_evidence_caps_each_line(monkeypatch):
    long_line = "j" * 5000

    def fake_run(args, **kwargs):
        if args[0] == "journalctl":
            return _proc(long_line + "\n")
        return _proc("")

    monkeypatch.setattr(evidence_module.subprocess, "run", fake_run)
    incident = Incident(
        kind="service",
        severity="CRITICAL",
        title="Service down",
        summary="",
        fingerprint="service:test",
        details={"service": "nginx", "unit": "nginx.service"},
    )

    result = EvidenceCollector().collect(incident)

    assert "journalctl" in result
    _assert_line_cap(result)


def test_systemctl_evidence_caps_each_line(monkeypatch):
    long_line = "s" * 5000

    def fake_run(args, **kwargs):
        if args[0] == "systemctl":
            return _proc("", long_line)
        return _proc("")

    monkeypatch.setattr(evidence_module.subprocess, "run", fake_run)
    incident = Incident(
        kind="service",
        severity="CRITICAL",
        title="Service down",
        summary="",
        fingerprint="service:test",
        details={"service": "nginx", "unit": "nginx.service"},
    )

    result = EvidenceCollector().collect(incident)

    assert "systemctl status" in result
    _assert_line_cap(result)


def test_service_evidence_caps_total_size(monkeypatch):
    many_lines = "\n".join(["x" * 5000 for _ in range(20)])

    def fake_run(args, **kwargs):
        if args[0] == "journalctl":
            return _proc(many_lines + "\n")
        return _proc("")

    monkeypatch.setattr(evidence_module.subprocess, "run", fake_run)
    incident = Incident(
        kind="service",
        severity="CRITICAL",
        title="Service down",
        summary="",
        fingerprint="service:test",
        details={"service": "nginx", "unit": "nginx.service"},
    )

    result = EvidenceCollector().collect(incident)

    assert len(result) <= 16384
    assert "[truncated]" in result
