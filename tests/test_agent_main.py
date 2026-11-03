"""Tests for the CLI entry point."""

import sys
from types import SimpleNamespace

from server_agent import agent as agent_module


class FakeConfig:
    def __init__(
        self,
        channel="telegram",
        error=None,
        service_profile="auto",
        services_required=None,
        services_optional=None,
        services=None,
        auto_detect_environment=False,
        auto_detect_services=False,
    ):
        self.alert_channel = channel
        self._error = error
        self.service_profile = service_profile
        self.services_required = list(services_required or [])
        self.services_optional = list(services_optional or [])
        self.services = list(services or [])
        self.auto_detect_environment = auto_detect_environment
        self.auto_detect_services = auto_detect_services

    def normalized(self):
        return self, list(getattr(self, "warnings", []))

    def validate(self):
        if self._error:
            raise ValueError(self._error)


def _patch_config(monkeypatch, channel="telegram", error=None, **kwargs):
    cfg = FakeConfig(channel=channel, error=error, **kwargs)
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


def test_check_config_prints_service_plan(monkeypatch, capsys):
    _patch_config(
        monkeypatch,
        service_profile="cpanel",
        services_required=["httpd", "mysql"],
        services_optional=["redis"],
        auto_detect_environment=False,
    )
    _patch_agent(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["server_agent", "--check-config"])

    assert agent_module.main() == 0
    out = capsys.readouterr().out
    assert "Configuration OK" in out
    assert "Service profile: cpanel (explicit)" in out
    assert "Required: httpd, mysql" in out
    assert "Optional: redis" in out


def test_check_config_auto_uses_detected_panel(monkeypatch, capsys):
    _patch_config(
        monkeypatch,
        service_profile="auto",
        services_required=[],
        services_optional=[],
        auto_detect_environment=True,
    )
    _patch_agent(monkeypatch)
    monkeypatch.setattr(
        agent_module,
        "EnvironmentDetector",
        lambda logger=None: SimpleNamespace(
            detect=lambda: SimpleNamespace(panel="cPanel/WHM")
        ),
    )
    monkeypatch.setattr(sys, "argv", ["server_agent", "--check-config"])

    assert agent_module.main() == 0
    out = capsys.readouterr().out
    assert "Service profile: cpanel (auto)" in out
    assert "Required: cpanel, mysql, exim, dovecot" in out


def test_check_config_explicit_profile_skips_panel_detection(monkeypatch, capsys):
    _patch_config(
        monkeypatch,
        service_profile="cpanel",
        services_required=["httpd"],
        services_optional=[],
        auto_detect_environment=True,
    )
    _patch_agent(monkeypatch)
    calls = []

    class Detector:
        def __init__(self, logger=None):
            calls.append(logger)

        def detect(self):
            return SimpleNamespace(panel="cPanel/WHM")

    monkeypatch.setattr(agent_module, "EnvironmentDetector", Detector)
    monkeypatch.setattr(sys, "argv", ["server_agent", "--check-config"])

    assert agent_module.main() == 0
    out = capsys.readouterr().out
    assert "Service profile: cpanel (explicit)" in out
    assert calls == []


def test_check_config_legacy_services_skip_panel_detection(monkeypatch, capsys):
    _patch_config(
        monkeypatch,
        service_profile="auto",
        services=["nginx"],
        auto_detect_environment=True,
        auto_detect_services=False,
    )
    _patch_agent(monkeypatch)
    calls = []

    class Detector:
        def __init__(self, logger=None):
            calls.append(logger)

        def detect(self):
            return SimpleNamespace(panel="cPanel/WHM")

    monkeypatch.setattr(agent_module, "EnvironmentDetector", Detector)
    monkeypatch.setattr(sys, "argv", ["server_agent", "--check-config"])

    assert agent_module.main() == 0
    out = capsys.readouterr().out
    assert "Required: nginx" in out
    assert calls == []


def test_version_prints_and_skips_config(monkeypatch, capsys):
    import server_agent

    monkeypatch.setattr(
        agent_module, "Config", lambda: (_ for _ in ()).throw(AssertionError("config used"))
    )
    monkeypatch.setattr(sys, "argv", ["prog", "--version"])

    assert agent_module.main() == 0
    assert capsys.readouterr().out.strip() == f"server-ai-agent {server_agent.__version__}"


def test_status_prints_raw_file_without_config(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("STATE_DIR", str(tmp_path))
    raw = '{"version": "1.0.0", "queue_depth": 0}\n'
    (tmp_path / "status.json").write_text(raw)
    monkeypatch.setattr(
        agent_module, "Config", lambda: (_ for _ in ()).throw(AssertionError("config used"))
    )
    monkeypatch.setattr(sys, "argv", ["prog", "--status"])

    assert agent_module.main() == 0
    assert capsys.readouterr().out == raw


def test_status_missing_file_reports_path_without_config(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("STATE_DIR", str(tmp_path))
    monkeypatch.setattr(
        agent_module, "Config", lambda: (_ for _ in ()).throw(AssertionError("config used"))
    )
    monkeypatch.setattr(sys, "argv", ["prog", "--status"])

    assert agent_module.main() == 1
    err = capsys.readouterr().err
    assert f"No status available at {tmp_path / 'status.json'}" in err


def test_main_prints_config_normalization_warnings(monkeypatch, capsys):
    cfg = _patch_config(monkeypatch)
    cfg.warnings = ["HEALTH_INTERVAL=1 is below minimum 10; using 10"]
    monkeypatch.setattr(sys, "argv", ["prog", "--check-config"])

    assert agent_module.main() == 0
    assert "HEALTH_INTERVAL=1" in capsys.readouterr().err


def test_test_ai_disabled_returns_1(monkeypatch, capsys):
    _patch_config(monkeypatch)
    FakeAgent = _patch_agent(monkeypatch)

    class FakeAgentWithAI(FakeAgent):
        def __init__(self, cfg):
            super().__init__(cfg)
            self.ai = SimpleNamespace(enabled=False, provider="deepseek")

    monkeypatch.setattr(agent_module, "Agent", FakeAgentWithAI)
    monkeypatch.setattr(sys, "argv", ["prog", "--test-ai"])

    assert agent_module.main() == 1
    assert "AI analysis is disabled or API key is missing" in capsys.readouterr().err


def test_test_ai_success_returns_0(monkeypatch, capsys):
    _patch_config(monkeypatch)
    FakeAgent = _patch_agent(monkeypatch)

    class FakeAgentWithAI(FakeAgent):
        def __init__(self, cfg):
            super().__init__(cfg)
            self.ai = SimpleNamespace(
                enabled=True,
                provider="deepseek",
                model="deepseek-chat",
                base_url="https://api.deepseek.com/v1",
                analyze=lambda inc: "Likely cause:\nTest passed.",
            )

    monkeypatch.setattr(agent_module, "Agent", FakeAgentWithAI)
    monkeypatch.setattr(sys, "argv", ["prog", "--test-ai"])

    assert agent_module.main() == 0
    out = capsys.readouterr().out
    assert "AI Diagnosis received successfully" in out
    assert "Test passed" in out
