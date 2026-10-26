"""Tests for the CLI entry point."""

import sys
from types import SimpleNamespace

from server_agent import agent as agent_module


class FakeConfig:
    def __init__(self, channel="telegram", error=None):
        self.alert_channel = channel
        self._error = error

    def validate(self):
        if self._error:
            raise ValueError(self._error)


def _patch_config(monkeypatch, channel="telegram", error=None):
    cfg = FakeConfig(channel=channel, error=error)
    monkeypatch.setattr(agent_module, "Config", lambda: cfg)
    return cfg


def _patch_agent(monkeypatch, primary=True, escalation=None, error=None):
    class FakeAgent:
        last = None

        def __init__(self, cfg):
            if error:
                raise RuntimeError(error)
            FakeAgent.last = self
            self.notifier = SimpleNamespace(send_test=lambda: primary)
            self.escalation_notifier = (
                None
                if escalation is None
                else SimpleNamespace(send_test=lambda: escalation)
            )
            self.ran_once = False
            self.ran = False

        def run_once(self):
            self.ran_once = True

        def run(self):
            self.ran = True

        def stop(self, *args):
            pass

    monkeypatch.setattr(agent_module, "Agent", FakeAgent)
    return FakeAgent


def test_check_config_prints_ok(monkeypatch, capsys):
    _patch_config(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["prog", "--check-config"])

    assert agent_module.main() == 0
    assert "Configuration OK" in capsys.readouterr().out


def test_validation_error_returns_2(monkeypatch, capsys):
    _patch_config(monkeypatch, error="bad config")
    monkeypatch.setattr(sys, "argv", ["prog"])

    assert agent_module.main() == 2
    assert "bad config" in capsys.readouterr().err


def test_check_heartbeat_returns_result(monkeypatch):
    _patch_config(monkeypatch)
    monkeypatch.setattr(agent_module, "_check_heartbeat", lambda cfg: 0)
    monkeypatch.setattr(sys, "argv", ["prog", "--check-heartbeat"])

    assert agent_module.main() == 0


def test_check_heartbeat_error_returns_2(monkeypatch, capsys):
    _patch_config(monkeypatch)

    def _boom(cfg):
        raise RuntimeError("boom")

    monkeypatch.setattr(agent_module, "_check_heartbeat", _boom)
    monkeypatch.setattr(sys, "argv", ["prog", "--check-heartbeat"])

    assert agent_module.main() == 2
    assert "Heartbeat check error: boom" in capsys.readouterr().err


def test_agent_construction_error_returns_2(monkeypatch, capsys):
    _patch_config(monkeypatch)
    _patch_agent(monkeypatch, error="agent boom")
    monkeypatch.setattr(sys, "argv", ["prog", "--test-notification"])

    assert agent_module.main() == 2
    assert "agent boom" in capsys.readouterr().err


def test_test_email_requires_email_channel(monkeypatch, capsys):
    _patch_config(monkeypatch, channel="telegram")
    _patch_agent(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["prog", "--test-email"])

    assert agent_module.main() == 2
    assert "--test-email requires ALERT_CHANNEL=email" in capsys.readouterr().err


def test_test_notification_succeeds(monkeypatch):
    _patch_config(monkeypatch)
    _patch_agent(monkeypatch, primary=True)
    monkeypatch.setattr(sys, "argv", ["prog", "--test-notification"])

    assert agent_module.main() == 0


def test_test_notification_escalation_failure_returns_1(monkeypatch):
    _patch_config(monkeypatch)
    _patch_agent(monkeypatch, primary=True, escalation=False)
    monkeypatch.setattr(sys, "argv", ["prog", "--test-notification"])

    assert agent_module.main() == 1


def test_once_runs_single_cycle(monkeypatch):
    _patch_config(monkeypatch)
    FakeAgent = _patch_agent(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["prog", "--once"])

    assert agent_module.main() == 0
    assert FakeAgent.last.ran_once is True
    assert FakeAgent.last.ran is False


def test_run_installs_handlers_and_runs(monkeypatch):
    _patch_config(monkeypatch)
    FakeAgent = _patch_agent(monkeypatch)
    installed = []
    monkeypatch.setattr(
        agent_module.signal,
        "signal",
        lambda signum, handler: installed.append(signum),
    )
    monkeypatch.setattr(sys, "argv", ["prog"])

    assert agent_module.main() == 0
    assert FakeAgent.last.ran is True
    assert len(installed) == 2
