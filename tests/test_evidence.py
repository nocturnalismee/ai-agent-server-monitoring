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
