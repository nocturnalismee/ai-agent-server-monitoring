from types import SimpleNamespace

from server_agent.models import Incident
from server_agent.telegram import TelegramNotifier, _truncate_html, _utf16_len


def _notifier(thread_id=None):
    config = SimpleNamespace(
        telegram_chat_id="-1001234567890",
        telegram_message_thread_id=thread_id,
        server_name="test-server",
        environment="test",
    )
    return TelegramNotifier(config, logger=SimpleNamespace())


def test_payload_uses_optional_thread_id():
    payload = _notifier(42)._payload(Incident(
        kind="test", severity="INFO", title="Test", summary="OK", fingerprint="test"
    ))
    assert payload["chat_id"] == "-1001234567890"
    assert payload["message_thread_id"] == 42
    assert payload["disable_web_page_preview"] is True


def test_payload_omits_empty_thread_id_and_bounds_text():
    payload = _notifier()._payload(Incident(
        kind="test", severity="INFO", title="Test", summary="x" * 5000, fingerprint="test"
    ))
    assert "message_thread_id" not in payload
    assert len(payload["text"]) <= 4096


def test_truncation_rebalances_html_tags():
    text = "<pre>" + ("a" * 5000) + "</pre>"
    result = _truncate_html(text, 4096)
    assert _utf16_len(result) <= 4096
    assert result.count("<pre>") == result.count("</pre>")
    assert result.endswith("</pre>\n…<i>[truncated]</i>")


def test_truncation_never_splits_emoji_and_respects_utf16_limit():
    text = "<b>" + ("🔴" * 3000) + "</b>"
    result = _truncate_html(text, 4096)
    assert _utf16_len(result) <= 4096
    # A split surrogate pair would fail to encode as UTF-16.
    result.encode("utf-16")
    assert result.count("<b>") == result.count("</b>")


def test_long_message_keeps_html_balanced():
    payload = _notifier()._payload(Incident(
        kind="health",
        severity="WARNING",
        title="Disk nearly full 🔴",
        summary="🟡" * 5000,
        fingerprint="disk",
        details={"raw_log": "x" * 5000},
    ))
    text = payload["text"]
    assert _utf16_len(text) <= 4096
    for tag in ("pre", "code", "b", "i"):
        assert text.count(f"<{tag}>") == text.count(f"</{tag}>")


def test_low_severity_alerts_are_silent_but_tests_and_critical_are_not():
    info = _notifier()._payload(Incident(
        kind="health", severity="INFO", title="t", summary="", fingerprint="f"
    ))
    critical = _notifier()._payload(Incident(
        kind="health", severity="CRITICAL", title="t", summary="", fingerprint="f"
    ))
    test = _notifier()._payload(Incident(
        kind="test", severity="INFO", title="t", summary="", fingerprint="test"
    ))
    assert info["disable_notification"] is True
    assert "disable_notification" not in critical
    assert "disable_notification" not in test
