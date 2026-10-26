import logging
from dataclasses import replace

from server_agent.agent import Agent, _build_notifier, _severity_at_least
from server_agent.core.config import Config
from server_agent.core.models import Incident


class _FakeState:
    def __init__(self):
        self.marked = []

    def can_alert(self, fingerprint, cooldown):
        return True

    def mark_alert_sent(self, fingerprint, cooldown):
        self.marked.append(fingerprint)


class _FakeNotifier:
    def __init__(self, result=True):
        self.result = result
        self.sent = []

    def send(self, incident):
        self.sent.append(incident)
        return self.result


class _FakeAI:
    def analyze(self, incident):
        return ""

    def close(self):
        pass


def _config(**overrides):
    return replace(Config(), **overrides)


def _incident(severity):
    return Incident(
        kind="health",
        severity=severity,
        title="test incident",
        summary="test summary",
        fingerprint="fp:test",
    )


def _process(severity, escalation, primary_ok=True):
    agent = object.__new__(Agent)
    agent.cfg = _config(alert_cooldown_seconds=900, escalation_min_severity="CRITICAL")
    agent.log = logging.getLogger("test.escalation")
    agent.state = _FakeState()
    agent.evidence_collector = None
    agent.ai = _FakeAI()
    agent.notifier = _FakeNotifier(primary_ok)
    agent.escalation_notifier = escalation
    agent._process(_incident(severity))
    return agent


def test_build_notifier_redirects_escalation_to_central_chat():
    cfg = _config(
        alert_channel="telegram",
        telegram_bot_token="main-token",
        telegram_chat_id="100",
        telegram_message_thread_id=None,
        escalation_channel="telegram",
        escalation_telegram_bot_token="",
        escalation_telegram_chat_id="-200",
        escalation_telegram_message_thread_id=42,
    )

    primary, escalation = _build_notifier(cfg, logging.getLogger("test"))

    assert primary.cfg.telegram_chat_id == "100"
    assert escalation is not None
    assert escalation.cfg.telegram_chat_id == "-200"
    assert escalation.cfg.telegram_bot_token == "main-token"
    assert escalation.cfg.telegram_message_thread_id == 42


def test_build_notifier_returns_none_when_escalation_disabled():
    cfg = _config(alert_channel="telegram", telegram_chat_id="100")
    _, escalation = _build_notifier(cfg, logging.getLogger("test"))
    assert escalation is None


def test_severity_threshold_ordering():
    assert _severity_at_least("CRITICAL", "CRITICAL")
    assert _severity_at_least("CRITICAL", "WARNING")
    assert not _severity_at_least("WARNING", "CRITICAL")
    assert not _severity_at_least("INFO", "WARNING")
    assert _severity_at_least("UNKNOWN", "INFO")


def test_critical_incident_goes_to_primary_and_escalation():
    escalation = _FakeNotifier(True)

    agent = _process("CRITICAL", escalation)

    assert len(agent.notifier.sent) == 1
    assert len(escalation.sent) == 1
    assert agent.state.marked == ["fp:test"]


def test_warning_incident_skips_escalation_when_min_is_critical():
    escalation = _FakeNotifier(True)

    agent = _process("WARNING", escalation)

    assert len(agent.notifier.sent) == 1
    assert escalation.sent == []
    assert agent.state.marked == ["fp:test"]


def test_escalation_success_marks_alert_when_primary_fails():
    agent = _process("CRITICAL", _FakeNotifier(True), primary_ok=False)

    assert agent.state.marked == ["fp:test"]
