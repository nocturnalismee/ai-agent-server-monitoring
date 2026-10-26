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
