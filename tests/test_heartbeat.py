from datetime import datetime, timezone

from server_agent.agent import (
    _heartbeat_age_seconds,
    _heartbeat_is_stale,
    _parse_heartbeat,
)


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


def test_stale_heartbeat_detected_after_threshold():
    now = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
    assert _heartbeat_is_stale("2026-10-26T11:50:00+00:00", 300, now)
