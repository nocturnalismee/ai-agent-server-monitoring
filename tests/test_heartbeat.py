import json
from dataclasses import replace
from datetime import datetime, timezone

from server_agent import agent as agent_module
from server_agent.agent import (
    _heartbeat_age_seconds,
    _heartbeat_is_stale,
    _parse_heartbeat,
)
from server_agent.core.config import Config
from server_agent.core.state import StateStore


def test_heartbeat_age_uses_timezone_aware_timestamp():
    now = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
    assert _heartbeat_age_seconds("2026-10-26T11:59:00+00:00", now) == 60
    assert _heartbeat_age_seconds("2026-10-26T11:59:00Z", now) == 60


def test_missing_or_invalid_heartbeat_is_treated_as_stale():
    assert _heartbeat_age_seconds(None) is None
    assert _parse_heartbeat("not-a-timestamp") is None
    assert _heartbeat_is_stale(None, 300)
    assert _heartbeat_is_stale("not-a-timestamp", 300)


def test_fresh_heartbeat_is_not_stale_and_future_is_tolerated():
    now = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
    assert not _heartbeat_is_stale("2026-10-26T11:59:30+00:00", 300, now)
    assert not _heartbeat_is_stale("2026-10-26T12:05:00+00:00", 300, now)


def test_future_heartbeat_age_is_clamped_to_zero():
    now = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
    assert _heartbeat_age_seconds("2026-10-26T12:05:00+00:00", now) == 0


def test_stale_heartbeat_detected_after_threshold():
    now = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
    assert _heartbeat_is_stale("2026-10-26T11:50:00+00:00", 300, now)


class _CapturingNotifier:
    def __init__(self):
        self.sent = []

    def send(self, incident):
        self.sent.append(incident)
        return True


def _watchdog_config(tmp_path):
    return replace(
        Config(),
        alert_channel="telegram",
        telegram_bot_token="token",
        telegram_chat_id="123",
        state_dir=tmp_path,
        log_file=tmp_path / "agent.log",
        auto_detect_environment=False,
    )


def test_watchdog_uses_separate_cooldown_and_leaves_state_json_untouched(
    tmp_path, monkeypatch
):
    cfg = _watchdog_config(tmp_path)
    state = StateStore(tmp_path)
    state.set_heartbeat("2020-01-01T00:00:00+00:00")
    state_before = (tmp_path / "state.json").read_bytes()
    notifier = _CapturingNotifier()
    monkeypatch.setattr(
        agent_module,
        "_build_notifier",
        lambda cfg, log, metadata=None: (notifier, None),
    )

    assert agent_module._check_heartbeat(cfg) == 0

    assert len(notifier.sent) == 1
    assert notifier.sent[0].fingerprint == "agent:heartbeat"
    assert (tmp_path / "state.json").read_bytes() == state_before
    watchdog = json.loads((tmp_path / "watchdog-alert.json").read_text())
    assert "agent:heartbeat" in watchdog["alerts"]

    assert agent_module._check_heartbeat(cfg) == 0

    assert len(notifier.sent) == 1
    assert (tmp_path / "state.json").read_bytes() == state_before
