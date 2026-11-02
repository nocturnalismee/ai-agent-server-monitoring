from dataclasses import replace

import pytest

from server_agent.core.config import Config


def _valid_config(**overrides):
    base = replace(
        Config(),
        alert_channel="telegram",
        telegram_bot_token="token",
        telegram_chat_id="123",
    )
    return replace(base, **overrides) if overrides else base


def test_defaults_validate_with_posix_paths():
    _valid_config().validate()


def test_relative_web_log_is_rejected():
    cfg = _valid_config(web_error_logs=["relative/error.log"])
    with pytest.raises(ValueError, match="WEB_ERROR_LOGS entries must be absolute"):
        cfg.validate()


def test_escalation_requires_chat_id():
    cfg = _valid_config(
        escalation_channel="telegram",
        escalation_telegram_chat_id="",
    )
    with pytest.raises(ValueError, match="ESCALATION_TELEGRAM_CHAT_ID"):
        cfg.validate()


def test_invalid_log_format_is_rejected():
    cfg = _valid_config(log_format="xml")
    with pytest.raises(ValueError, match="LOG_FORMAT"):
        cfg.validate()


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.com/v1",
        "ftp://api.example.com/v1",
        "//api.example.com/v1",
        "api.example.com/v1",
    ],
)
def test_non_https_ai_base_url_is_rejected(url):
    cfg = _valid_config(ai_base_url=url)
    with pytest.raises(ValueError, match="AI_BASE_URL must use https://"):
        cfg.validate()


@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.com/v1",
        "http://localhost:8080/v1",
        "http://127.0.0.1:8080/v1",
        "http://[::1]:8080/v1",
    ],
)
def test_https_or_loopback_ai_base_url_is_allowed(url):
    _valid_config(ai_base_url=url).validate()
