import json
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

from server_agent.core.models import Incident, ServerMetadata
from server_agent.notifiers import telegram as telegram_module
from server_agent.notifiers.telegram import (
    TelegramNotifier,
    _close_open_tags,
    _format_ai_text,
    _format_card,
    _truncate_html,
    _utf16_len,
)


def _incident(**overrides):
    data = {
        "kind": "health",
        "severity": "WARNING",
        "title": "Disk full",
        "summary": "Disk is nearly full.",
        "fingerprint": "disk",
        "timestamp": "2026-10-26T12:34:56+00:00",
        "details": {},
        "ai_analysis": "",
    }
    data.update(overrides)
    return Incident(**data)


def _notifier(thread_id=None, metadata=None):
    config = SimpleNamespace(
        telegram_chat_id="-1001234567890",
        telegram_message_thread_id=thread_id,
        telegram_bot_token="bot-token",
        telegram_timeout=7,
        server_name="app.example.com",
        environment="production",
    )
    logger = SimpleNamespace(info=Mock(), error=Mock())
    return TelegramNotifier(config, logger=logger, metadata=metadata), logger


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.payload


def test_format_card_aligns_keys_and_escapes_values():
    card = _format_card([("A", "one"), ("LONG", "<tag> &")])

    assert card == "<pre>A    : one\nLONG : &lt;tag&gt; &amp;</pre>"
    assert _format_card([]) == ""


def test_format_ai_text_formats_code_bold_and_headers():
    raw = (
        "**Likely cause:** disk full\n"
        "Immediate checks:\n"
        "Run `df -h` & <b>\n"
        "**Risk:** high"
    )

    formatted = _format_ai_text(raw)

    assert "<b>Likely cause:</b> disk full" in formatted
    assert "<b>Immediate checks:</b>" in formatted
    assert "Run <code>df -h</code> &amp; &lt;b&gt;" in formatted
    assert "<b>Risk:</b> high" in formatted
    assert _format_ai_text("") == ""
    assert _format_ai_text("Likely cause:\n- check") == "<b>Likely cause:</b>\n- check"


def test_message_contains_summary_details_raw_log_ai_and_footer():
    notifier, _ = _notifier(
        metadata=ServerMetadata(
            os_name="Ubuntu",
            os_version="22.04",
            panel="Standalone",
            web_server="nginx",
        )
    )
    incident = _incident(
        title="Disk & full",
        summary="Disk & full <now>",
        details={
            "service": "nginx",
            "cpu": "99%",
            "empty": "",
            "raw_log": "line1\nline2",
        },
        ai_analysis="**Risk:** high",
    )

    message = notifier._message(incident)

    assert "[app] WARNING: Disk &amp; full" in message
    assert "Ubuntu 22.04 · nginx" in message
    assert "2026-10-26 12:34 UTC" in message
    assert "<code>Disk &amp; full &lt;now&gt;</code>" in message
    assert "SERVICE : nginx" in message
    assert "EMPTY   : —" in message
    assert "<code>line1\nline2</code>" in message
    assert "<b>Risk:</b> high" in message
    assert message.endswith("<i>app.example.com · production</i>")


def test_message_uses_profile_and_skips_optional_sections_without_metadata():
    notifier, _ = _notifier()
    incident = _incident(
        summary="",
        details={},
        ai_analysis="",
        timestamp="not-a-date",
    )

    message = notifier._message(incident)

    assert "PROFILE : production" in message
    assert "not-a-date" in message
    assert "Summary" not in message
    assert "Details" not in message
    assert "AI Diagnosis" not in message
    assert message.endswith("<i>app.example.com · production</i>")


def test_payload_thread_and_notification_sound_rules():
    info = _notifier(thread_id=7)[0]._payload(
        _incident(kind="health", severity="INFO")
    )
    recovery = _notifier()[0]._payload(
        _incident(kind="health", severity="RECOVERY")
    )
    test = _notifier()[0]._payload(_incident(kind="test", severity="INFO"))
    critical = _notifier()[0]._payload(_incident(kind="health", severity="CRITICAL"))

    assert info["message_thread_id"] == 7
    assert info["disable_notification"] is True
    assert recovery["disable_notification"] is True
    assert "disable_notification" not in test
    assert "disable_notification" not in critical


def test_send_success_posts_expected_payload(monkeypatch):
    notifier, logger = _notifier()
    captured = {}

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return _Response(json.dumps({"ok": True}).encode("utf-8"))

    monkeypatch.setattr(telegram_module, "urlopen", fake_urlopen)

    assert notifier.send(_incident()) is True
    assert captured["timeout"] == 7
    assert captured["request"].full_url == (
        "https://api.telegram.org/botbot-token/sendMessage"
    )
    body = json.loads(captured["request"].data.decode("utf-8"))
    assert body["chat_id"] == "-1001234567890"
    assert body["parse_mode"] == "HTML"
    logger.info.assert_called_once_with(
        "Telegram alert sent: severity=%s title=%s",
        "WARNING",
        "Disk full",
    )
    logger.error.assert_not_called()


def test_send_rejected_response_returns_false(monkeypatch):
    notifier, logger = _notifier()
    response = _Response(
        json.dumps(
            {"ok": False, "description": "Bad Request: chat not found"}
        ).encode("utf-8")
    )
    monkeypatch.setattr(telegram_module, "urlopen", lambda request, timeout: response)

    assert notifier.send(_incident()) is False
    logger.error.assert_called_once()
    assert logger.error.call_args.args[0] == "Telegram API rejected alert: %s"
    assert "chat not found" in logger.error.call_args.args[1]


def test_send_http_error_returns_false(monkeypatch):
    notifier, logger = _notifier()

    def fake_urlopen(request, timeout):
        raise HTTPError(request.full_url, 500, "Server Error", None, None)

    monkeypatch.setattr(telegram_module, "urlopen", fake_urlopen)

    assert notifier.send(_incident()) is False
    logger.error.assert_called_once_with("Telegram API returned HTTP %s", 500)


def test_send_url_error_returns_false(monkeypatch):
    notifier, logger = _notifier()
    error = URLError("dns failure")

    def fake_urlopen(request, timeout):
        raise error

    monkeypatch.setattr(telegram_module, "urlopen", fake_urlopen)

    assert notifier.send(_incident()) is False
    logger.error.assert_called_once_with(
        "Telegram alert delivery failed: %s",
        error,
    )


def test_send_test_builds_test_incident():
    notifier, _ = _notifier()
    notifier.send = Mock(return_value=True)

    assert notifier.send_test() is True
    incident = notifier.send.call_args.args[0]
    assert incident.kind == "test"
    assert incident.severity == "INFO"
    assert incident.title == "Server AI Agent test"
    assert incident.fingerprint == "test"
    assert incident.details == {"status": "ok", "transport": "telegram"}


def test_close_open_tags_handles_nested_unclosed_and_stray_tags():
    assert _close_open_tags("<b><code>x") == "</code></b>"
    assert _close_open_tags("<b>x</i>") == "</b>"
    assert _close_open_tags("<b>x</b>") == ""
    assert _close_open_tags("plain text") == ""


def test_truncate_html_already_fits_and_zero_limit():
    assert _truncate_html("<b>ok</b>", 100) == "<b>ok</b>"
    assert _truncate_html("x" * 100, 20) == "\n…<i>[truncated]</i>"
    assert _truncate_html("x" * 100, 0) == ""


def test_truncate_html_cuts_at_newline_before_appending_marker():
    result = _truncate_html("first\n" + ("x" * 100), 30)

    assert result == "first\n…<i>[truncated]</i>"
    assert _utf16_len(result) <= 30


def test_truncate_html_drops_incomplete_tag_at_cut_boundary():
    result = _truncate_html(("x" * 9) + '<a href="' + ("y" * 100), 30)

    assert result == ("x" * 9) + "\n…<i>[truncated]</i>"
    assert '<a href="' not in result
    assert _utf16_len(result) <= 30


def test_truncate_html_respects_utf16_boundaries_for_emoji():
    text = "🔴" * 100

    assert _utf16_len(text) == 200
    assert _truncate_html(text, 200) == text

    result = _truncate_html(text + "x", 200)
    assert _utf16_len(result) <= 200
    result.encode("utf-16")
    assert result.endswith("…<i>[truncated]</i>")
