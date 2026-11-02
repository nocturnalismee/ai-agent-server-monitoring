import queue
import threading
from types import SimpleNamespace

from server_agent.agent import Agent


def _bare_agent():
    agent = object.__new__(Agent)
    agent._alert_queue = queue.Queue(maxsize=10)
    agent._alert_stop = object()
    agent.log = SimpleNamespace(
        info=lambda *a, **k: None,
        warning=lambda *a, **k: None,
        exception=lambda *a, **k: None,
    )
    agent.ai = SimpleNamespace(close=lambda: None)
    agent._alert_worker = threading.Thread(
        target=agent._alert_worker_loop, name="test-worker", daemon=True
    )
    agent._alert_worker.start()
    return agent


def test_dispatch_is_processed_asynchronously_and_drained():
    agent = _bare_agent()
    seen = []
    agent._process = lambda incident: seen.append(incident)

    agent.dispatch("incident-1")
    agent.dispatch("incident-2")
    agent.drain()

    assert seen == ["incident-1", "incident-2"]
    agent._shutdown_worker(timeout=2)
    assert not agent._alert_worker.is_alive()


def test_worker_survives_processing_errors():
    agent = _bare_agent()
    seen = []

    def process(incident):
        seen.append(incident)
        if incident == "boom":
            raise RuntimeError("simulated failure")

    agent._process = process
    agent.dispatch("boom")
    agent.dispatch("after")
    agent.drain()

    assert seen == ["boom", "after"]
    agent._shutdown_worker(timeout=2)
    assert not agent._alert_worker.is_alive()


def test_run_once_dispatches_all_monitors_and_drains():
    agent = _bare_agent()
    collected = []
    agent.state = SimpleNamespace(set_heartbeat=lambda: None)
    agent.health = SimpleNamespace(collect=lambda: ["health-1"])
    agent.web = SimpleNamespace(collect=lambda: ["web-1"])
    agent.ssh = SimpleNamespace(collect=lambda: ["ssh-1"])
    agent.kernel = SimpleNamespace(collect=lambda: ["kernel-1"])
    agent.dispatch = collected.append
    agent.drain = lambda: collected.append("drained")

    agent.run_once()

    assert collected == ["health-1", "web-1", "ssh-1", "kernel-1", "drained"]

    agent._shutdown_worker(timeout=2)


def test_run_loops_once_then_shuts_down(monkeypatch):
    import server_agent.agent as agent_module

    agent = _bare_agent()
    agent.running = True
    agent.state = SimpleNamespace(set_heartbeat=lambda: None)
    agent.cfg = SimpleNamespace(
        server_name="srv1",
        environment="production",
        health_interval=0,
        log_interval=0,
    )
    agent.metadata = None
    agent.health = SimpleNamespace(collect=lambda: ["health-1"])
    agent.web = SimpleNamespace(collect=lambda: ["web-1"])
    agent.ssh = SimpleNamespace(collect=lambda: ["ssh-1"])
    agent.kernel = SimpleNamespace(collect=lambda: ["kernel-1"])
    seen = []
    agent.dispatch = seen.append
    agent.ai = SimpleNamespace(close=lambda: seen.append("closed"))

    def _sleep(_seconds):
        agent.running = False

    monkeypatch.setattr(agent_module.time, "sleep", _sleep)

    agent.run()

    assert seen[:4] == ["health-1", "web-1", "ssh-1", "kernel-1"]
    assert "closed" in seen
    assert not agent._alert_worker.is_alive()


def test_run_once_isolates_monitor_failures():
    agent = _bare_agent()
    collected = []
    agent.state = SimpleNamespace(set_heartbeat=lambda: None)

    def fail():
        raise RuntimeError("collector exploded")

    agent.health = SimpleNamespace(collect=fail)
    agent.web = SimpleNamespace(collect=fail)
    agent.ssh = SimpleNamespace(collect=lambda: ["ssh-1"])
    agent.kernel = SimpleNamespace(collect=lambda: ["kernel-1"])
    agent.dispatch = collected.append
    agent.drain = lambda: collected.append("drained")

    agent.run_once()

    assert collected == ["ssh-1", "kernel-1", "drained"]

    agent._shutdown_worker(timeout=2)


def test_run_isolates_monitors_and_respects_intervals(monkeypatch):
    import server_agent.agent as agent_module

    agent = _bare_agent()
    agent.running = True
    agent.state = SimpleNamespace(set_heartbeat=lambda: None)
    agent.cfg = SimpleNamespace(
        server_name="srv1",
        environment="production",
        health_interval=10,
        log_interval=5,
    )
    agent.metadata = None

    calls = {"health": 0, "web": 0, "ssh": 0, "kernel": 0}
    exceptions = []

    def failing(name):
        def collect():
            calls[name] += 1
            raise RuntimeError(name + " exploded")

        return collect

    def healthy(name):
        def collect():
            calls[name] += 1
            return []

        return collect

    agent.health = SimpleNamespace(collect=failing("health"))
    agent.web = SimpleNamespace(collect=failing("web"))
    agent.ssh = SimpleNamespace(collect=healthy("ssh"))
    agent.kernel = SimpleNamespace(collect=healthy("kernel"))
    agent.dispatch = lambda incident: None
    agent.log = SimpleNamespace(
        info=lambda *a, **k: None,
        warning=lambda *a, **k: None,
        exception=lambda *a, **k: exceptions.append(a),
    )

    clock = {"now": 1000.0}
    monkeypatch.setattr(agent_module.time, "monotonic", lambda: clock["now"])

    def sleep(seconds):
        clock["now"] += seconds
        if clock["now"] >= 1011:
            agent.running = False

    monkeypatch.setattr(agent_module.time, "sleep", sleep)

    agent.run()

    assert calls["health"] == 2
    assert calls["web"] == 3
    assert calls["ssh"] == 3
    assert calls["kernel"] == 3
    assert len(exceptions) == 5
    assert not agent._alert_worker.is_alive()


def test_alert_rate_limit_blocks_excess_and_does_not_mark_cooldown():
    from server_agent.core.models import Incident

    agent = _bare_agent()
    agent.cfg = SimpleNamespace(
        alert_cooldown_seconds=900,
        escalation_min_severity="CRITICAL",
        alert_rate_limit_per_minute=2,
    )
    marked = []
    agent.state = SimpleNamespace(
        can_alert=lambda fingerprint, cooldown: True,
        mark_alert_sent=lambda fingerprint, cooldown: marked.append(fingerprint),
    )
    agent.evidence_collector = None
    agent.ai = SimpleNamespace(analyze=lambda incident: "", close=lambda: None)
    sent = []
    agent.notifier = SimpleNamespace(send=lambda incident: sent.append(incident) or True)
    agent.escalation_notifier = None
    warnings = []
    agent.log = SimpleNamespace(
        info=lambda *a, **k: None,
        warning=lambda message, *args: warnings.append(message % args),
        exception=lambda *a, **k: None,
    )

    for index in range(3):
        agent._process(
            Incident(
                kind="health",
                severity="INFO",
                title="title",
                summary="summary",
                fingerprint=f"fp:{index}",
            )
        )

    assert [incident.fingerprint for incident in sent] == ["fp:0", "fp:1"]
    assert marked == ["fp:0", "fp:1"]
    assert len(warnings) == 1
    assert warnings[0].startswith("Alert rate limit reached")

    agent._shutdown_worker(timeout=2)


def test_ai_failure_does_not_suppress_alert():
    from server_agent.core.models import Incident

    agent = _bare_agent()
    agent.cfg = SimpleNamespace(
        alert_cooldown_seconds=900,
        escalation_min_severity="CRITICAL",
    )
    marked = []
    agent.state = SimpleNamespace(
        can_alert=lambda fingerprint, cooldown: True,
        mark_alert_sent=lambda fingerprint, cooldown: marked.append(fingerprint),
    )
    agent.evidence_collector = None

    def _fail(_incident):
        raise RuntimeError("provider exploded")

    agent.ai = SimpleNamespace(analyze=_fail, close=lambda: None)
    sent = []
    agent.notifier = SimpleNamespace(send=lambda incident: sent.append(incident) or True)
    agent.escalation_notifier = None

    incident = Incident(
        kind="health",
        severity="CRITICAL",
        title="CPU high",
        summary="CPU is 99%",
        fingerprint="health:CPU",
    )
    agent._process(incident)

    assert len(sent) == 1
    assert marked == ["health:CPU"]
    agent._shutdown_worker(timeout=2)
    assert not agent._alert_worker.is_alive()


def test_ai_result_is_sanitized_before_assignment(monkeypatch):
    import server_agent.agent as agent_module
    from server_agent.core.models import Incident

    agent = _bare_agent()
    agent.cfg = SimpleNamespace(
        alert_cooldown_seconds=900,
        escalation_min_severity="CRITICAL",
    )
    agent.state = SimpleNamespace(
        can_alert=lambda fingerprint, cooldown: True,
        mark_alert_sent=lambda fingerprint, cooldown: None,
    )
    agent.evidence_collector = None
    agent.ai = SimpleNamespace(
        analyze=lambda _incident: "leaked token=supersecret", close=lambda: None
    )
    sent = []
    agent.notifier = SimpleNamespace(send=lambda incident: sent.append(incident) or True)
    agent.escalation_notifier = None
    monkeypatch.setattr(agent_module, "sanitize_incident", lambda incident: incident)

    incident = Incident(
        kind="health",
        severity="WARNING",
        title="CPU high",
        summary="CPU is 99%",
        fingerprint="health:CPU",
    )
    agent._process(incident)

    assert len(sent) == 1
    assert "supersecret" not in sent[0].ai_analysis
    assert "[REDACTED]" in sent[0].ai_analysis
    agent._shutdown_worker(timeout=2)
    assert not agent._alert_worker.is_alive()


class _FullQueue:
    def put_nowait(self, _item):
        raise queue.Full


class _CapturingQueue:
    def __init__(self):
        self.items = []

    def put_nowait(self, item):
        self.items.append(item)

    def qsize(self):
        return len(self.items)


def test_dispatch_counts_seen_and_dropped_when_queue_is_full():
    agent = object.__new__(Agent)
    agent.log = SimpleNamespace(
        info=lambda *a, **k: None,
        warning=lambda *a, **k: None,
        exception=lambda *a, **k: None,
        debug=lambda *a, **k: None,
    )
    agent._alert_queue = _FullQueue()

    agent.dispatch(SimpleNamespace(fingerprint="fp:full"))

    assert agent._counter_snapshot() == {
        "seen": 1,
        "sent": 0,
        "suppressed": 0,
        "dropped": 1,
        "delivery_errors": 0,
    }


def _process_agent(**overrides):
    from server_agent.core.models import Incident

    agent = object.__new__(Agent)
    agent.cfg = SimpleNamespace(
        alert_cooldown_seconds=900,
        escalation_min_severity="CRITICAL",
        alert_rate_limit_per_minute=0,
    )
    agent.log = SimpleNamespace(
        info=lambda *a, **k: None,
        warning=lambda *a, **k: None,
        exception=lambda *a, **k: None,
        debug=lambda *a, **k: None,
    )
    agent.state = SimpleNamespace(
        can_alert=lambda fingerprint, cooldown: True,
        mark_alert_sent=lambda fingerprint, cooldown: None,
    )
    agent.evidence_collector = None
    agent.ai = SimpleNamespace(analyze=lambda incident: "", close=lambda: None)
    agent.notifier = SimpleNamespace(send=lambda incident: True)
    agent.escalation_notifier = None
    for name, value in overrides.items():
        setattr(agent, name, value)
    return agent, Incident(
        kind="health",
        severity="INFO",
        title="title",
        summary="summary",
        fingerprint="fp:1",
    )


def test_process_counts_suppressed_duplicate():
    agent, incident = _process_agent()
    agent.state.can_alert = lambda fingerprint, cooldown: False

    agent._process(incident)

    assert agent._counter_snapshot()["suppressed"] == 1
    assert agent._counter_snapshot()["sent"] == 0


def test_process_counts_dropped_when_rate_limited():
    agent, incident = _process_agent()
    agent._alert_rate_limited = lambda: True

    agent._process(incident)

    assert agent._counter_snapshot()["dropped"] == 1


def test_process_counts_sent_when_delivered():
    agent, incident = _process_agent()

    agent._process(incident)

    assert agent._counter_snapshot()["sent"] == 1
    assert agent._counter_snapshot()["delivery_errors"] == 0


def test_process_counts_delivery_error_when_send_fails():
    agent, incident = _process_agent()
    agent.notifier = SimpleNamespace(send=lambda incident: False)

    agent._process(incident)

    assert agent._counter_snapshot()["sent"] == 0
    assert agent._counter_snapshot()["delivery_errors"] == 1


def test_run_once_writes_status_file_with_counters_and_durations(tmp_path):
    import json

    agent = _bare_agent()
    agent.cfg = SimpleNamespace(
        server_name="srv1",
        state_dir=tmp_path,
    )
    agent.counters = {
        "seen": 2,
        "sent": 1,
        "suppressed": 0,
        "dropped": 1,
        "delivery_errors": 0,
    }
    agent.state = SimpleNamespace(set_heartbeat=lambda: None)
    agent.health = SimpleNamespace(collect=lambda: [])
    agent.web = SimpleNamespace(collect=lambda: [])
    agent.ssh = SimpleNamespace(collect=lambda: [])
    agent.kernel = SimpleNamespace(collect=lambda: [])
    agent.drain = lambda: None

    agent.run_once()

    status = json.loads((tmp_path / "status.json").read_text())
    assert status["version"] == agent_module_version()
    assert status["server_name"] == "srv1"
    assert status["queue_depth"] == 0
    assert status["counters"] == agent.counters
    assert set(status["cycle_durations_ms"]) == {"health", "logs"}
    assert status["cycle_durations_ms"]["health"] >= 0
    assert status["cycle_durations_ms"]["logs"] >= 0
    assert status["updated_at"]
    assert status["last_cycle_ts"]

    agent._shutdown_worker(timeout=2)


def agent_module_version():
    import server_agent

    return server_agent.__version__


def test_process_spools_failed_delivery_and_retry_succeeds(tmp_path):
    from server_agent.core.models import Incident
    from server_agent.core.spool import IncidentSpool

    agent, incident = _process_agent()
    agent.spool = IncidentSpool(tmp_path)
    agent.notifier = SimpleNamespace(send=lambda incident: False)

    agent._process(incident)

    assert agent._counter_snapshot()["delivery_errors"] == 1
    due = agent.spool.due()
    assert len(due) == 1
    assert due[0][1]["fingerprint"] == "fp:1"

    delivered = []
    agent.notifier = SimpleNamespace(
        send=lambda stored: delivered.append(stored) or True
    )
    agent._retry_spooled()

    assert [stored.fingerprint for stored in delivered] == ["fp:1"]
    assert agent.spool.due() == []
    assert agent._counter_snapshot()["sent"] == 1
    assert isinstance(incident, Incident)


def test_process_spools_rate_limited_alert(tmp_path):
    from server_agent.core.spool import IncidentSpool

    agent, incident = _process_agent()
    agent.spool = IncidentSpool(tmp_path)
    agent._alert_rate_limited = lambda: True

    agent._process(incident)

    entries = agent.spool.due()
    assert len(entries) == 1
    assert entries[0][1]["fingerprint"] == "fp:1"
    assert agent._counter_snapshot()["dropped"] == 1


def test_dispatch_spools_when_queue_is_full(tmp_path):
    from server_agent.core.models import Incident
    from server_agent.core.spool import IncidentSpool

    agent = object.__new__(Agent)
    agent.log = SimpleNamespace(
        info=lambda *a, **k: None,
        warning=lambda *a, **k: None,
        exception=lambda *a, **k: None,
        debug=lambda *a, **k: None,
    )
    agent._alert_queue = _FullQueue()
    agent.spool = IncidentSpool(tmp_path)

    agent.dispatch(
        Incident(
            kind="health",
            severity="INFO",
            title="title",
            summary="summary",
            fingerprint="fp:full",
        )
    )

    entries = agent.spool.due()
    assert len(entries) == 1
    assert entries[0][1]["fingerprint"] == "fp:full"


def test_process_counts_delivery_error_when_send_raises():
    agent, incident = _process_agent()

    def _boom(_incident):
        raise RuntimeError("transport exploded")

    agent.notifier = SimpleNamespace(send=_boom)

    agent._process(incident)

    assert agent._counter_snapshot()["sent"] == 0
    assert agent._counter_snapshot()["delivery_errors"] == 1


def test_retry_spooled_does_not_run_ai(tmp_path):
    from server_agent.core.spool import IncidentSpool

    agent, incident = _process_agent()
    agent.spool = IncidentSpool(tmp_path)
    agent.notifier = SimpleNamespace(send=lambda stored: False)
    agent._process(incident)

    analyzed = []
    agent.ai = SimpleNamespace(
        analyze=lambda stored: analyzed.append(stored) or "",
        close=lambda: None,
    )
    agent.notifier = SimpleNamespace(send=lambda stored: True)

    agent._retry_spooled()

    assert analyzed == []
    assert agent.spool.due() == []


def test_retry_uses_mark_attempt_when_delivery_still_fails(tmp_path):
    from server_agent.core.spool import IncidentSpool

    agent, incident = _process_agent()
    agent.spool = IncidentSpool(tmp_path)
    agent.notifier = SimpleNamespace(send=lambda stored: False)
    agent._process(incident)

    agent._retry_spooled()

    key = IncidentSpool.key_for("fp:1")
    stored = __import__("json").loads(
        (agent.spool.directory / f"{key}.json").read_text()
    )
    assert stored["attempts"] == 1
    assert agent.spool.due() == []


def test_run_once_writes_status_when_drain_fails(tmp_path):
    import pytest

    agent = _bare_agent()
    agent.cfg = SimpleNamespace(server_name="srv1", state_dir=tmp_path)
    agent.state = SimpleNamespace(set_heartbeat=lambda: None)
    agent.health = SimpleNamespace(collect=lambda: [])
    agent.web = SimpleNamespace(collect=lambda: [])
    agent.ssh = SimpleNamespace(collect=lambda: [])
    agent.kernel = SimpleNamespace(collect=lambda: [])

    def _boom():
        raise RuntimeError("drain failed")

    agent.drain = _boom

    with pytest.raises(RuntimeError):
        agent.run_once()

    assert (tmp_path / "status.json").exists()
    agent._shutdown_worker(timeout=2)
