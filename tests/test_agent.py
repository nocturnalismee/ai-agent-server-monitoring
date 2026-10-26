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
