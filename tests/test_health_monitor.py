from types import SimpleNamespace

from server_agent.monitors import health as health_module
from server_agent.monitors.health import HealthMonitor


class FakeState:
    def __init__(self):
        self.active = {}

    def set_health_active(self, key, active):
        previous = self.active.get(key, False)
        self.active[key] = active
        return previous


def make_config(**overrides):
    base = {
        "auto_detect_services": False,
        "services": ["nginx"],
        "cpu_warning": 80,
        "cpu_critical": 90,
        "memory_warning": 80,
        "memory_critical": 90,
        "disk_warning": 80,
        "disk_critical": 90,
        "load_warning_per_cpu": 1.5,
        "load_critical_per_cpu": 2.5,
        "disk_paths": ["/"],
        "alert_on_missing_service": False,
        "recovery_alerts": True,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def make_monitor(**overrides):
    return HealthMonitor(make_config(**overrides), FakeState(), logger=None)


def test_severity_levels():
    assert HealthMonitor._severity(95, 80, 90) == "CRITICAL"
    assert HealthMonitor._severity(85, 80, 90) == "WARNING"
    assert HealthMonitor._severity(50, 80, 90) is None


def test_metric_incident_warning_then_critical():
    monitor = make_monitor()
    warning = monitor._metric_incident("CPU", 85.0, 80, 90)
    assert warning is not None
    assert warning.kind == "health"
    assert warning.severity == "WARNING"
    assert warning.fingerprint == "health:CPU"
    assert warning.details["value"] == 85.0

    critical = monitor._metric_incident("CPU", 95.0, 80, 90)
    assert critical is not None
    assert critical.severity == "CRITICAL"


def test_metric_incident_recovery_appears_once():
    monitor = make_monitor()
    assert monitor._metric_incident("CPU", 95.0, 80, 90) is not None
    recovery = monitor._metric_incident("CPU", 10.0, 80, 90)
    assert recovery is not None
    assert recovery.kind == "recovery"
    assert recovery.severity == "INFO"
    assert recovery.fingerprint == "recovery:health:CPU"
    assert monitor._metric_incident("CPU", 10.0, 80, 90) is None


def test_metric_incident_recovery_disabled():
    monitor = make_monitor(recovery_alerts=False)
    assert monitor._metric_incident("CPU", 95.0, 80, 90) is not None
    assert monitor._metric_incident("CPU", 10.0, 80, 90) is None


def test_service_state_parses_systemctl(monkeypatch):
    monitor = make_monitor()

    def fake_run(args, **kwargs):
        return SimpleNamespace(returncode=0, stdout="active\n", stderr="")

    monkeypatch.setattr(health_module.subprocess, "run", fake_run)
    assert monitor._service_state("nginx") == ("active", "")

    monkeypatch.setattr(
        health_module.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=3, stdout="inactive\n", stderr=""),
    )
    assert monitor._service_state("nginx") == ("inactive", "")

    monkeypatch.setattr(
        health_module.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="not found"),
    )
    assert monitor._service_state("nginx") == ("not found", "")

    def missing(*args, **kwargs):
        raise FileNotFoundError("systemctl")

    monkeypatch.setattr(health_module.subprocess, "run", missing)
    state, error = monitor._service_state("nginx")
    assert state == "unknown"
    assert "systemctl" in error


def _patch_metrics(monkeypatch, cpu=10.0, memory=20.0, load1=0.5, cpu_count=2, disk=30.0):
    monkeypatch.setattr(health_module.psutil, "cpu_percent", lambda interval=None: cpu)
    monkeypatch.setattr(
        health_module.psutil, "virtual_memory", lambda: SimpleNamespace(percent=memory)
    )
    monkeypatch.setattr(health_module.psutil, "cpu_count", lambda: cpu_count)
    monkeypatch.setattr(health_module.psutil, "disk_usage", lambda path: SimpleNamespace(percent=disk))
    monkeypatch.setattr(
        health_module.os, "getloadavg", lambda: (load1, load1, load1), raising=False
    )


def test_collect_healthy_returns_no_incidents(monkeypatch):
    monitor = make_monitor()
    _patch_metrics(monkeypatch)
    monkeypatch.setattr(monitor, "_service_state", lambda service: ("active", ""))
    assert monitor.collect() == []


def test_collect_reports_each_threshold(monkeypatch):
    monitor = make_monitor()
    _patch_metrics(monkeypatch, cpu=95.0, memory=85.0, load1=5.0, cpu_count=2, disk=90.0)
    monkeypatch.setattr(monitor, "_service_state", lambda service: ("active", ""))

    incidents = monitor.collect()
    by_metric = {item.details.get("metric"): item for item in incidents}

    assert by_metric["CPU"].severity == "CRITICAL"
    assert by_metric["Memory"].severity == "WARNING"
    assert by_metric["Load-per-CPU"].severity == "CRITICAL"
    assert by_metric["Load-per-CPU"].details["load_1m"] == 5.0
    assert by_metric["Load-per-CPU"].details["cpu_count"] == 2
    assert by_metric["Disk /"].severity == "CRITICAL"


def test_collect_skips_disk_when_unreadable(monkeypatch):
    monitor = make_monitor()
    _patch_metrics(monkeypatch)

    def denied(path):
        raise PermissionError(path)

    monkeypatch.setattr(health_module.psutil, "disk_usage", denied)
    monkeypatch.setattr(monitor, "_service_state", lambda service: ("active", ""))
    assert monitor.collect() == []


def test_collect_reports_service_down_then_recovery(monkeypatch):
    monitor = make_monitor()
    _patch_metrics(monkeypatch)
    monkeypatch.setattr(monitor, "_service_state", lambda service: ("failed", ""))

    down = monitor.collect()
    assert len(down) == 1
    assert down[0].kind == "service"
    assert down[0].severity == "CRITICAL"
    assert down[0].details["service"] == "nginx"

    monkeypatch.setattr(monitor, "_service_state", lambda service: ("active", ""))
    recovered = monitor.collect()
    assert len(recovered) == 1
    assert recovered[0].kind == "recovery"
    assert recovered[0].fingerprint == "recovery:service:nginx"


def test_collect_ignores_missing_service_by_default(monkeypatch):
    monitor = make_monitor()
    _patch_metrics(monkeypatch)
    monkeypatch.setattr(monitor, "_service_state", lambda service: ("not-found", ""))
    assert monitor.collect() == []


def test_collect_alerts_on_missing_service_when_enabled(monkeypatch):
    monitor = make_monitor(alert_on_missing_service=True)
    _patch_metrics(monkeypatch)
    monkeypatch.setattr(monitor, "_service_state", lambda service: ("not-found", ""))

    incidents = monitor.collect()
    assert len(incidents) == 1
    assert incidents[0].kind == "service"
    assert incidents[0].severity == "CRITICAL"


def test_collect_skips_unknown_service_before_tracking(monkeypatch):
    monitor = make_monitor()
    _patch_metrics(monkeypatch)
    monkeypatch.setattr(monitor, "_service_state", lambda service: ("unknown", "boom"))

    assert monitor.collect() == []
    assert "service:nginx" not in monitor.state.active
