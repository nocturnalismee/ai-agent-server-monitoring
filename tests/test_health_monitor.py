from types import SimpleNamespace

from server_agent.detectors.services import ResolvedService
from server_agent.monitors import health as health_module
from server_agent.monitors.health import HealthMonitor


class FakeState:
    def __init__(self):
        self.active = {}
        self.service_failures = {}

    def set_health_active(self, key, active):
        previous = self.active.get(key, False)
        self.active[key] = active
        return previous

    def service_failure_count(self, key):
        return self.service_failures.get(key, 0)

    def increment_service_failure(self, key):
        self.service_failures[key] = self.service_failures.get(key, 0) + 1
        return self.service_failures[key]

    def clear_service_failure(self, key):
        self.service_failures.pop(key, None)


class FakeResolver:
    def __init__(self, mapping):
        self.mapping = mapping

    def resolve(self, name):
        return self.mapping[name]


def make_config(**overrides):
    base = {
        "auto_detect_services": False,
        "services": ["nginx"],
        "service_profile": "auto",
        "services_required": [],
        "services_optional": [],
        "service_failure_threshold": 2,
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
    monitor = HealthMonitor(make_config(**overrides), FakeState(), logger=None)
    monitor.resolver = FakeResolver(
        {"nginx": ResolvedService("nginx", "nginx.service", True, "installed")}
    )
    return monitor


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
    monitor = make_monitor(
        services=[],
        service_profile="none",
        services_optional=["nginx"],
    )
    _patch_metrics(monkeypatch)
    monitor.resolver = FakeResolver(
        {"nginx": ResolvedService("nginx", "nginx.service", False, "not-found")}
    )
    assert monitor.collect() == []


def test_collect_alerts_on_unknown_optional_service_when_enabled(monkeypatch):
    monitor = make_monitor(
        services=[],
        service_profile="none",
        services_optional=["nginx"],
        alert_on_missing_service=True,
    )
    _patch_metrics(monkeypatch)
    monitor.resolver = FakeResolver(
        {"nginx": ResolvedService("nginx", "nginx.service", False, "unknown")}
    )

    incidents = monitor.collect()
    assert len(incidents) == 1
    assert incidents[0].kind == "service"
    assert incidents[0].severity == "WARNING"
    assert incidents[0].details["required"] is False


def test_collect_skips_unknown_service_before_tracking(monkeypatch):
    monitor = make_monitor(
        services=[],
        service_profile="none",
        services_optional=["nginx"],
    )
    _patch_metrics(monkeypatch)
    monitor.resolver = FakeResolver(
        {"nginx": ResolvedService("nginx", "nginx.service", False, "unknown")}
    )

    assert monitor.collect() == []
    assert "service:nginx" not in monitor.state.active


def _service_monitor(monkeypatch, mapping, is_active):
    monitor = make_monitor(services=[])
    monitor.cfg.service_profile = "none"
    monitor.cfg.services_required = ["mysql"]
    monitor.cfg.services_optional = ["redis"]
    monitor.cfg.service_failure_threshold = 2
    monitor.cfg.alert_on_missing_service = False
    monitor.cfg.recovery_alerts = True
    monitor.resolver = FakeResolver(mapping)
    monkeypatch.setattr(
        monitor, "_service_state", lambda unit: is_active(unit)
    )
    return monitor


def test_required_missing_service_is_critical(monkeypatch):
    mapping = {
        "mysql": ResolvedService("mysql", "mysql.service", False, "not-found"),
        "redis": ResolvedService("redis", "redis.service", True, "installed"),
    }
    monitor = _service_monitor(monkeypatch, mapping, lambda unit: ("active", ""))
    incidents = monitor.collect_services()
    assert len(incidents) == 1
    assert incidents[0].severity == "CRITICAL"
    assert incidents[0].details["unit"] == "mysql.service"
    assert incidents[0].details["required"] is True


def test_optional_missing_service_is_skipped(monkeypatch):
    mapping = {
        "mysql": ResolvedService("mysql", "mysql.service", True, "installed"),
        "redis": ResolvedService("redis", "redis.service", False, "not-found"),
    }
    monitor = _service_monitor(monkeypatch, mapping, lambda unit: ("active", ""))
    assert monitor.collect_services() == []


def test_service_alert_waits_for_threshold(monkeypatch):
    mapping = {
        "mysql": ResolvedService("mysql", "mysql.service", True, "installed"),
        "redis": ResolvedService("redis", "redis.service", True, "installed"),
    }
    monitor = _service_monitor(
        monkeypatch,
        mapping,
        lambda unit: ("active", "") if unit == "redis.service" else ("inactive", ""),
    )
    assert monitor.collect_services() == []
    incidents = monitor.collect_services()
    assert len(incidents) == 1
    assert incidents[0].severity == "CRITICAL"
    assert incidents[0].details["consecutive_failures"] == 2


def test_failed_service_alerts_immediately(monkeypatch):
    mapping = {
        "mysql": ResolvedService("mysql", "mysql.service", True, "installed"),
        "redis": ResolvedService("redis", "redis.service", True, "installed"),
    }
    monitor = _service_monitor(
        monkeypatch,
        mapping,
        lambda unit: ("active", "") if unit == "redis.service" else ("failed", "boom"),
    )
    incidents = monitor.collect_services()
    assert len(incidents) == 1
    assert incidents[0].severity == "CRITICAL"
    assert incidents[0].details["state"] == "failed"
    assert incidents[0].details["error"] == "boom"


def test_optional_failed_is_warning_immediately(monkeypatch):
    mapping = {
        "mysql": ResolvedService("mysql", "mysql.service", True, "installed"),
        "redis": ResolvedService("redis", "redis.service", True, "installed"),
    }
    monitor = _service_monitor(
        monkeypatch,
        mapping,
        lambda unit: ("failed", "boom") if unit == "redis.service" else ("active", ""),
    )
    incidents = monitor.collect_services()
    assert len(incidents) == 1
    assert incidents[0].severity == "WARNING"
    assert incidents[0].details["required"] is False
    assert incidents[0].details["state"] == "failed"
    assert incidents[0].details["error"] == "boom"


def test_optional_inactive_is_warning_at_threshold(monkeypatch):
    mapping = {
        "mysql": ResolvedService("mysql", "mysql.service", True, "installed"),
        "redis": ResolvedService("redis", "redis.service", True, "installed"),
    }
    monitor = _service_monitor(
        monkeypatch,
        mapping,
        lambda unit: (
            ("inactive", "") if unit == "redis.service" else ("active", "")
        ),
    )
    assert monitor.collect_services() == []
    incidents = monitor.collect_services()
    assert len(incidents) == 1
    assert incidents[0].severity == "WARNING"
    assert incidents[0].details["required"] is False


def test_active_service_clears_counter_and_emits_recovery(monkeypatch):
    mapping = {
        "mysql": ResolvedService("mysql", "mysql.service", True, "installed"),
        "redis": ResolvedService("redis", "redis.service", True, "installed"),
    }
    monitor = _service_monitor(
        monkeypatch,
        mapping,
        lambda unit: ("active", "") if unit == "redis.service" else ("failed", "boom"),
    )
    monitor.collect_services()
    monitor._service_state = lambda unit: ("active", "")
    incidents = monitor.collect_services()
    assert len(incidents) == 1
    assert incidents[0].kind == "recovery"
    assert incidents[0].severity == "INFO"
    assert monitor.state.service_failure_count("service:mysql") == 0
    assert monitor.collect_services() == []


def test_duplicate_unit_required_wins(monkeypatch):
    mapping = {
        "mysql": ResolvedService("mysql", "mysql.service", True, "installed"),
        "mariadb": ResolvedService("mariadb", "mysql.service", True, "installed"),
    }
    monitor = _service_monitor(
        monkeypatch,
        mapping,
        lambda unit: ("inactive", ""),
    )
    monitor.cfg.services_required = ["mysql"]
    monitor.cfg.services_optional = ["mariadb"]
    monitor.cfg.service_failure_threshold = 1
    incidents = monitor.collect_services()
    assert len(incidents) == 1
    assert incidents[0].details["service"] == "mysql"
    assert incidents[0].details["unit"] == "mysql.service"
    assert incidents[0].details["required"] is True
    assert incidents[0].severity == "CRITICAL"


def test_unknown_required_is_warning(monkeypatch):
    mapping = {
        "mysql": ResolvedService("mysql", "mysql.service", False, "unknown"),
        "redis": ResolvedService("redis", "redis.service", True, "installed"),
    }
    monitor = _service_monitor(monkeypatch, mapping, lambda unit: ("active", ""))
    incidents = monitor.collect_services()
    assert len(incidents) == 1
    assert incidents[0].severity == "WARNING"
    assert incidents[0].details["state"] == "unknown"
