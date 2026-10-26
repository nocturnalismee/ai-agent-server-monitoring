"""Tests for the SMTP email notifier."""

from types import SimpleNamespace

import pytest

from server_agent.core.models import Incident
from server_agent.notifiers import emailer as emailer_module
from server_agent.notifiers.emailer import EmailNotifier


class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout, context=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        self.calls = []
        self.messages = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def starttls(self, context=None):
        self.calls.append(("starttls", context))

    def login(self, user, password):
        self.calls.append(("login", user, password))

    def send_message(self, message):
        self.messages.append(message)


@pytest.fixture(autouse=True)
def _reset_instances():
    FakeSMTP.instances.clear()
    yield
    FakeSMTP.instances.clear()


def _config(**overrides):
    values = {
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "smtp_security": "starttls",
        "smtp_username": "",
        "smtp_password": "",
        "smtp_from": "monitor@example.com",
        "smtp_to": ["ops@example.com"],
        "smtp_timeout": 10,
        "server_name": "web1",
        "environment": "production",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _logger():
    return SimpleNamespace(info=lambda *a, **k: None, exception=lambda *a, **k: None)


def _incident(**overrides):
    values = {
        "kind": "health",
        "severity": "CRITICAL",
        "title": "CPU high",
        "summary": "CPU is high",
        "fingerprint": "health:cpu",
        "details": {"metric": "CPU", "value": "99"},
    }
    values.update(overrides)
    return Incident(**values)


def test_ssl_connection_uses_smtp_ssl(monkeypatch):
    context = object()
    monkeypatch.setattr(emailer_module.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(emailer_module.smtplib, "SMTP_SSL", FakeSMTP)

    conn = EmailNotifier(_config(smtp_security="ssl"), _logger())._connect()

    assert isinstance(conn, FakeSMTP)
    assert conn.context is context
    assert conn.host == "smtp.example.com"
    assert conn.port == 587


def test_starttls_connection_calls_ehlo_and_starttls(monkeypatch):
    context = object()
    monkeypatch.setattr(emailer_module.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(emailer_module.smtplib, "SMTP", FakeSMTP)

    conn = EmailNotifier(_config(smtp_security="starttls"), _logger())._connect()

    assert conn.calls == ["ehlo", ("starttls", context), "ehlo"]


def test_plain_connection_skips_starttls(monkeypatch):
    monkeypatch.setattr(emailer_module.smtplib, "SMTP", FakeSMTP)

    conn = EmailNotifier(_config(smtp_security="none"), _logger())._connect()

    assert conn.calls == ["ehlo"]


def test_send_success_logs_in_and_builds_bodies(monkeypatch):
    monkeypatch.setattr(emailer_module.smtplib, "SMTP", FakeSMTP)
    events = []
    logger = _logger()
    logger.info = lambda *a, **k: events.append(a)
    metadata = SimpleNamespace(badge=lambda: "Ubuntu 22.04 · Nginx")
    notifier = EmailNotifier(
        _config(smtp_username="user", smtp_password="secret"),
        logger,
        metadata=metadata,
    )

    assert notifier.send(_incident(evidence="oom log", ai_analysis="restart")) is True

    conn = FakeSMTP.instances[-1]
    assert ("login", "user", "secret") in conn.calls
    msg = conn.messages[0]
    assert msg["Subject"] == "[CRITICAL] web1 - CPU high"
    assert msg["To"] == "ops@example.com"

    text = msg.get_body(("plain",)).get_content()
    assert "Server: web1" in text
    assert "Evidence logs:" in text
    assert "AI analysis & Troubleshooting:" in text
    assert "metric: CPU" in text

    html = msg.get_body(("html",)).get_content()
    assert "Ubuntu 22.04" in html
    assert "CPU high" in html
    assert events


def test_send_without_username_skips_login(monkeypatch):
    monkeypatch.setattr(emailer_module.smtplib, "SMTP", FakeSMTP)

    assert EmailNotifier(_config(), _logger()).send(_incident()) is True

    conn = FakeSMTP.instances[-1]
    assert not any(isinstance(call, tuple) and call[0] == "login" for call in conn.calls)


def test_send_failure_returns_false_and_logs(monkeypatch):
    class BoomSMTP(FakeSMTP):
        def send_message(self, message):
            raise RuntimeError("smtp down")

    monkeypatch.setattr(emailer_module.smtplib, "SMTP", BoomSMTP)
    errors = []
    logger = _logger()
    logger.exception = lambda *a, **k: errors.append(a)

    assert EmailNotifier(_config(), logger).send(_incident()) is False
    assert errors


def test_send_test_uses_info_severity(monkeypatch):
    monkeypatch.setattr(emailer_module.smtplib, "SMTP", FakeSMTP)

    assert EmailNotifier(_config(), _logger()).send_test() is True

    subject = FakeSMTP.instances[-1].messages[0]["Subject"]
    assert subject == "[INFO] web1 - Server AI Agent test"
