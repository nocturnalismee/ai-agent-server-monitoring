from types import SimpleNamespace

from server_agent.models import Incident
from server_agent.telegram import TelegramNotifier


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
