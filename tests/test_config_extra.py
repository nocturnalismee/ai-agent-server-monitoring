from dataclasses import replace

import pytest

from server_agent.core.config import Config


def _valid_config(**overrides):
    base = replace(
        Config(),
        alert_channel="telegram",
        telegram_bot_token="bot-token",
        telegram_chat_id="12345",
        telegram_message_thread_id=None,
        escalation_channel="none",
        escalation_telegram_bot_token="",
        escalation_telegram_chat_id="",
        escalation_telegram_message_thread_id=None,
        escalation_min_severity="CRITICAL",
        health_interval=60,
        log_interval=15,
        heartbeat_stale_seconds=300,
        log_format="text",
        cpu_warning=85.0,
        cpu_critical=95.0,
        memory_warning=85.0,
        memory_critical=95.0,
        disk_warning=85.0,
        disk_critical=95.0,
        load_warning_per_cpu=1.5,
        load_critical_per_cpu=2.5,
        max_log_lines_per_cycle=250,
        max_log_line_chars=4096,
        max_log_sample_chars=600,
        ssh_failure_tracked_ips_max=1000,
        web_error_logs=[],
        kernel_monitor_enabled=True,
        kernel_error_logs=[],
        smtp_host="",
        smtp_from="",
        smtp_to=[],
        smtp_security="starttls",
        smtp_port=587,
        smtp_timeout=20,
        telegram_timeout=10,
        ai_enabled=False,
        ai_provider="deepseek",
        ai_api_key="",
        ai_base_url="",
        ai_model="",
        ai_timeout_seconds=10,
        ai_max_output_tokens=400,
        ai_rate_limit_per_minute=10,
    )
    return replace(base, **overrides) if overrides else base


def _email_config(**overrides):
    values = {
        "alert_channel": "email",
        "smtp_host": "smtp.example.com",
        "smtp_from": "agent@example.com",
        "smtp_to": ["ops@example.com"],
    }
    values.update(overrides)
    return _valid_config(**values)


def _ai_config(**overrides):
    values = {
        "ai_enabled": True,
        "ai_api_key": "key",
        "ai_provider": "deepseek",
    }
    values.update(overrides)
    return _valid_config(**values)


def test_valid_telegram_config_with_thread_id():
    _valid_config(telegram_message_thread_id=7).validate()


def test_alert_channel_must_be_email_or_telegram():
    with pytest.raises(ValueError, match="ALERT_CHANNEL must be email or telegram"):
        _valid_config(alert_channel="slack").validate()


def test_email_config_requires_host_sender_recipients_and_security():
    cfg = _email_config(
        smtp_host="",
        smtp_from="",
        smtp_to=[],
        smtp_security="plain",
    )
    with pytest.raises(ValueError) as exc:
        cfg.validate()
    message = str(exc.value)
    assert "SMTP_HOST is required" in message
    assert "SMTP_FROM is required" in message
    assert "SMTP_TO must contain at least one recipient" in message
    assert "SMTP_SECURITY must be starttls or ssl" in message


def test_valid_email_config():
    _email_config().validate()


@pytest.mark.parametrize("port", [0, 65536])
def test_smtp_port_must_be_in_range(port):
    with pytest.raises(ValueError, match="SMTP_PORT must be between 1 and 65535"):
        _email_config(smtp_port=port).validate()


def test_telegram_requires_token_chat_and_positive_thread():
    cfg = _valid_config(
        telegram_bot_token="",
        telegram_chat_id="",
        telegram_message_thread_id=0,
    )
    with pytest.raises(ValueError) as exc:
        cfg.validate()
    message = str(exc.value)
    assert "TELEGRAM_BOT_TOKEN is required" in message
    assert "TELEGRAM_CHAT_ID is required" in message
    assert "TELEGRAM_MESSAGE_THREAD_ID must be a positive integer" in message


def test_escalation_channel_must_be_none_or_telegram():
    with pytest.raises(ValueError, match="ESCALATION_CHANNEL must be none or telegram"):
        _valid_config(escalation_channel="slack").validate()


def test_escalation_telegram_requires_token_chat_and_positive_thread():
    cfg = _valid_config(
        alert_channel="email",
        smtp_host="smtp.example.com",
        smtp_from="agent@example.com",
        smtp_to=["ops@example.com"],
        telegram_bot_token="",
        escalation_channel="telegram",
        escalation_telegram_bot_token="",
        escalation_telegram_chat_id="",
        escalation_telegram_message_thread_id=0,
    )
    with pytest.raises(ValueError) as exc:
        cfg.validate()
    message = str(exc.value)
    assert "ESCALATION_TELEGRAM_BOT_TOKEN" in message
    assert "ESCALATION_TELEGRAM_CHAT_ID is required" in message
    assert "ESCALATION_TELEGRAM_MESSAGE_THREAD_ID must be a positive integer" in message


def test_escalation_can_use_main_telegram_token():
    _valid_config(
        escalation_channel="telegram",
        escalation_telegram_chat_id="999",
        escalation_telegram_message_thread_id=3,
    ).validate()


def test_escalation_min_severity_must_be_warning_or_critical():
    cfg = _valid_config(escalation_min_severity="INFO")
    with pytest.raises(ValueError, match="ESCALATION_MIN_SEVERITY"):
        cfg.validate()


@pytest.mark.parametrize(
    ("health_interval", "log_interval"),
    [(9, 15), (60, 1)],
)
def test_intervals_must_not_be_too_aggressive(health_interval, log_interval):
    cfg = _valid_config(health_interval=health_interval, log_interval=log_interval)
    with pytest.raises(ValueError, match="Intervals are too aggressive"):
        cfg.validate()


def test_heartbeat_stale_seconds_must_be_at_least_sixty():
    with pytest.raises(ValueError, match="HEARTBEAT_STALE_SECONDS"):
        _valid_config(heartbeat_stale_seconds=59).validate()


def test_json_log_format_is_accepted():
    _valid_config(log_format="json").validate()


@pytest.mark.parametrize(
    ("field", "value", "label"),
    [
        ("cpu_warning", -1.0, "CPU"),
        ("memory_critical", 101.0, "MEMORY"),
        ("disk_warning", 96.0, "DISK"),
    ],
)
def test_resource_thresholds_must_be_ordered_and_bounded(field, value, label):
    cfg = _valid_config(**{field: value})
    with pytest.raises(ValueError, match=rf"{label} thresholds"):
        cfg.validate()


def test_load_thresholds_must_be_ordered_and_non_negative():
    cfg = _valid_config(load_warning_per_cpu=2.6)
    with pytest.raises(ValueError, match="Load thresholds"):
        cfg.validate()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("max_log_lines_per_cycle", 0, "MAX_LOG_LINES_PER_CYCLE"),
        ("max_log_lines_per_cycle", 10001, "MAX_LOG_LINES_PER_CYCLE"),
        ("max_log_line_chars", 255, "MAX_LOG_LINE_CHARS"),
        ("max_log_line_chars", 65537, "MAX_LOG_LINE_CHARS"),
        ("max_log_sample_chars", 99, "MAX_LOG_SAMPLE_CHARS"),
        ("max_log_sample_chars", 4097, "MAX_LOG_SAMPLE_CHARS"),
    ],
)
def test_log_limits_must_be_in_range(field, value, message):
    cfg = _valid_config(**{field: value})
    with pytest.raises(ValueError, match=message):
        cfg.validate()


@pytest.mark.parametrize("value", [0, 100001])
def test_ssh_tracked_ip_limit_must_be_in_range(value):
    cfg = _valid_config(ssh_failure_tracked_ips_max=value)
    with pytest.raises(ValueError, match="SSH_FAILURE_TRACKED_IPS_MAX"):
        cfg.validate()


def test_web_error_logs_support_at_most_twelve_paths():
    cfg = _valid_config(web_error_logs=[f"/var/log/web{i}.log" for i in range(13)])
    with pytest.raises(ValueError, match="WEB_ERROR_LOGS supports at most 12"):
        cfg.validate()


def test_kernel_error_logs_support_at_most_six_paths():
    cfg = _valid_config(kernel_error_logs=[f"/var/log/kernel{i}.log" for i in range(7)])
    with pytest.raises(ValueError, match="KERNEL_ERROR_LOGS supports at most 6"):
        cfg.validate()


def test_kernel_error_logs_must_be_absolute():
    cfg = _valid_config(kernel_error_logs=["relative/kernel.log"])
    with pytest.raises(ValueError, match="KERNEL_ERROR_LOGS entries must be absolute"):
        cfg.validate()


def test_timeouts_must_be_positive():
    cfg = _valid_config(
        smtp_timeout=0,
        telegram_timeout=0,
        ai_timeout_seconds=0,
    )
    with pytest.raises(ValueError, match="SMTP_TIMEOUT, TELEGRAM_TIMEOUT"):
        cfg.validate()


def test_ai_provider_allowlist_rejects_unknown_provider_without_base_url():
    cfg = _ai_config(ai_provider="unknown-provider")
    with pytest.raises(ValueError) as exc:
        cfg.validate()
    message = str(exc.value)
    assert "AI_PROVIDER must be one of" in message
    assert "AI_BASE_URL is required" in message


def test_ai_unknown_provider_with_base_url_is_allowed():
    _ai_config(ai_provider="unknown-provider", ai_base_url="https://ai.example/v1").validate()


def test_ai_requires_api_key():
    cfg = _ai_config(ai_api_key="")
    with pytest.raises(ValueError, match="AI_API_KEY is required"):
        cfg.validate()


@pytest.mark.parametrize("provider", ["custom", "openai_compatible"])
def test_ai_custom_providers_require_base_url(provider):
    cfg = _ai_config(ai_provider=provider)
    with pytest.raises(ValueError, match="AI_BASE_URL is required"):
        cfg.validate()


@pytest.mark.parametrize("tokens", [0, 8193])
def test_ai_max_output_tokens_must_be_in_range(tokens):
    cfg = _ai_config(ai_max_output_tokens=tokens)
    with pytest.raises(ValueError, match="AI_MAX_OUTPUT_TOKENS"):
        cfg.validate()


@pytest.mark.parametrize("rate", [0, 121])
def test_ai_rate_limit_must_be_in_range(rate):
    cfg = _ai_config(ai_rate_limit_per_minute=rate)
    with pytest.raises(ValueError, match="AI_RATE_LIMIT_PER_MINUTE"):
        cfg.validate()


@pytest.mark.parametrize(
    ("provider", "expected"),
    [
        ("deepseek", "deepseek-chat"),
        ("openai", "gpt-4o-mini"),
        ("kimi", "moonshot-v1-8k"),
        ("moonshot", "moonshot-v1-8k"),
        ("groq", "llama-3.3-70b-versatile"),
        ("openrouter", "deepseek/deepseek-chat"),
        ("claude", "claude-3-5-haiku-20241022"),
        ("anthropic", "claude-3-5-haiku-20241022"),
        ("gemini", "gemini-1.5-flash"),
        ("unknown", "deepseek-chat"),
    ],
)
def test_resolved_ai_model_defaults(provider, expected):
    assert _valid_config(ai_provider=provider).resolved_ai_model() == expected


def test_resolved_ai_model_prefers_explicit_value():
    cfg = _valid_config(ai_provider="openai", ai_model="custom-model")
    assert cfg.resolved_ai_model() == "custom-model"


@pytest.mark.parametrize(
    ("provider", "expected"),
    [
        ("deepseek", "https://api.deepseek.com/v1"),
        ("openai", "https://api.openai.com/v1"),
        ("kimi", "https://api.moonshot.cn/v1"),
        ("moonshot", "https://api.moonshot.cn/v1"),
        ("groq", "https://api.groq.com/openai/v1"),
        ("openrouter", "https://openrouter.ai/api/v1"),
        ("claude", "https://api.anthropic.com/v1"),
        ("anthropic", "https://api.anthropic.com/v1"),
        ("gemini", "https://generativelanguage.googleapis.com/v1beta/models"),
        ("unknown", "https://api.deepseek.com/v1"),
    ],
)
def test_resolved_ai_base_url_defaults(provider, expected):
    assert _valid_config(ai_provider=provider).resolved_ai_base_url() == expected


def test_resolved_ai_base_url_prefers_explicit_value_and_strips_slashes():
    cfg = _valid_config(ai_base_url="https://ai.example/v1///")
    assert cfg.resolved_ai_base_url() == "https://ai.example/v1"


def test_resolved_web_error_logs_dedupes_explicit_paths():
    cfg = _valid_config(web_error_logs=["/a.log", "", "/b.log", "/a.log"])
    assert cfg.resolved_web_error_logs() == ["/a.log", "/b.log"]


def test_resolved_web_error_logs_falls_back_to_standard_paths():
    cfg = _valid_config(
        web_error_logs=[],
        nginx_error_log="/nginx.log",
        apache_error_log="",
        apache_rhel_error_log="/apache.log",
    )
    assert cfg.resolved_web_error_logs() == ["/nginx.log", "/apache.log"]


def test_resolved_kernel_logs_dedupes_explicit_paths():
    cfg = _valid_config(kernel_error_logs=["/kern.log", "", "/kern.log", "/messages"])
    assert cfg.resolved_kernel_logs() == ["/kern.log", "/messages"]


def test_resolved_kernel_logs_falls_back_to_standard_paths():
    cfg = _valid_config(
        kernel_error_logs=[],
        kernel_log="/kern.log",
        kernel_log_rhel="",
    )
    assert cfg.resolved_kernel_logs() == ["/kern.log"]


def _cfg(**overrides):
    return replace(_valid_config(), **overrides)


def test_services_defaults_to_empty_without_legacy_env(monkeypatch):
    monkeypatch.delenv("SERVICES", raising=False)
    assert Config().services == []


def test_services_env_still_parses_legacy_override(monkeypatch):
    monkeypatch.setenv("SERVICES", "nginx,mysql")
    assert Config().services == ["nginx", "mysql"]


def test_service_profile_accepts_known_profiles():
    for name in ("auto", "none", "cpanel", "runcloud"):
        _cfg(service_profile=name).validate()


def test_service_profile_env_strips_quotes(monkeypatch):
    monkeypatch.setenv("SERVICE_PROFILE", "  'cpanel'  ")
    assert Config().service_profile == "cpanel"


def test_service_profile_rejects_unknown():
    with pytest.raises(ValueError, match="SERVICE_PROFILE"):
        _cfg(service_profile="bogus").validate()


def test_service_failure_threshold_bounds():
    for value in (1, 2, 10):
        _cfg(service_failure_threshold=value).validate()
    for value in (0, 11):
        with pytest.raises(ValueError, match="SERVICE_FAILURE_THRESHOLD"):
            _cfg(service_failure_threshold=value).validate()


def test_required_and_optional_overlap_is_rejected():
    with pytest.raises(ValueError, match="both required and optional"):
        _cfg(services_required=["nginx"], services_optional=["nginx"]).validate()


def test_invalid_service_unit_name_is_rejected():
    with pytest.raises(ValueError, match="invalid systemd unit name"):
        _cfg(services_required=["nginx; rm -rf /"]).validate()
