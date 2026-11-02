import pytest

import server_agent.agent as agent_module


@pytest.fixture(autouse=True)
def _enable_af_unix(monkeypatch):
    monkeypatch.setattr(agent_module.socket, "AF_UNIX", 1, raising=False)


class _FakeSocket:
    def __init__(self):
        self.connected = None
        self.sent = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def connect(self, path):
        self.connected = path

    def sendall(self, data):
        self.sent = data


def test_sd_notify_sends_message(monkeypatch):
    sock = _FakeSocket()
    monkeypatch.setenv("NOTIFY_SOCKET", "/run/systemd/notify")
    monkeypatch.setattr(agent_module.socket, "socket", lambda *a, **k: sock)

    agent_module._sd_notify("READY=1")

    assert sock.connected == "/run/systemd/notify"
    assert sock.sent == b"READY=1"


def test_sd_notify_translates_abstract_socket(monkeypatch):
    sock = _FakeSocket()
    monkeypatch.setenv("NOTIFY_SOCKET", "@/run/notify")
    monkeypatch.setattr(agent_module.socket, "socket", lambda *a, **k: sock)

    agent_module._sd_notify("WATCHDOG=1")

    assert sock.connected == "\0/run/notify"


def test_sd_notify_is_noop_without_socket(monkeypatch):
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    calls = []
    monkeypatch.setattr(agent_module.socket, "socket", lambda *a, **k: calls.append(1))

    agent_module._sd_notify("READY=1")

    assert calls == []


def test_sd_notify_swallows_oserror(monkeypatch):
    class _Boom(_FakeSocket):
        def connect(self, path):
            raise OSError("boom")

    monkeypatch.setenv("NOTIFY_SOCKET", "/run/systemd/notify")
    monkeypatch.setattr(agent_module.socket, "socket", lambda *a, **k: _Boom())

    agent_module._sd_notify("READY=1")
