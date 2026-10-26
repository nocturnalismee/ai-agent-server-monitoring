from types import SimpleNamespace
from unittest.mock import Mock

import server_agent.core.state as state_module
from server_agent.core.state import StateStore


def _storage(monkeypatch, now=1000.0, monotonic=0.0):
    clock = {"now": now, "monotonic": monotonic}
    monkeypatch.setattr(
        state_module,
        "time",
        SimpleNamespace(
            time=lambda: clock["now"],
            monotonic=lambda: clock["monotonic"],
        ),
    )
    return clock


def test_file_cursor_get_update_and_idempotent_update(tmp_path, monkeypatch):
    state = StateStore(tmp_path)
    assert state.file_cursor("/var/log/nginx/error.log") == {"inode": None, "offset": 0}

    state.update_file_cursor("/var/log/nginx/error.log", 123, 456)
    assert state.file_cursor("/var/log/nginx/error.log") == {"inode": 123, "offset": 456}

    save = Mock()
    monkeypatch.setattr(state, "save", save)
    state.update_file_cursor("/var/log/nginx/error.log", 123, 456)
    save.assert_not_called()
    state.update_file_cursor("/var/log/nginx/error.log", 123, 457)
    save.assert_called_once()


def test_journal_cursor_update_is_idempotent(tmp_path, monkeypatch):
    state = StateStore(tmp_path)
    state.update_journal_cursor("kernel", "cursor-1")

    save = Mock()
    monkeypatch.setattr(state, "save", save)
    state.update_journal_cursor("kernel", "cursor-1")
    save.assert_not_called()
    state.update_journal_cursor("auth", "cursor-2")
    save.assert_called_once()
    assert state.journal_cursor("kernel") == "cursor-1"
    assert state.journal_cursor("auth") == "cursor-2"


def test_alert_cooldown_gating(tmp_path, monkeypatch):
    clock = _storage(monkeypatch, now=1000.0)
    state = StateStore(tmp_path)

    assert state.can_alert("disk", cooldown=10) is True
    state.mark_alert_sent("disk", cooldown=10)
    assert state.can_alert("disk", cooldown=10) is False

    clock["now"] = 1009.9
    assert state.can_alert("disk", cooldown=10) is False
    clock["now"] = 1010.0
    assert state.can_alert("disk", cooldown=10) is True


def test_mark_alert_sent_prunes_stale_and_invalid_entries(tmp_path, monkeypatch):
    _storage(monkeypatch, now=100000.0)
    state = StateStore(tmp_path)
    state.data["alerts"] = {
        "old": 1000.0,
        "recent": 99900.0,
        "invalid": "not-a-number",
    }

    state.mark_alert_sent("new", cooldown=100)

    assert set(state.data["alerts"]) == {"recent", "new"}
    assert state.data["alerts"]["new"] == 100000.0


def test_ssh_failure_evicts_ip_with_oldest_latest_failure(tmp_path):
    state = StateStore(
        tmp_path,
        ssh_failure_tracked_ips_max=2,
        ssh_failure_persist_threshold=100,
    )
    state.add_ssh_failure("192.0.2.1", 100.0, window=300)
    state.add_ssh_failure("192.0.2.2", 200.0, window=300)
    state.add_ssh_failure("192.0.2.1", 300.0, window=300)
    state.add_ssh_failure("192.0.2.3", 250.0, window=300)

    assert set(state.data["ssh_failures"]) == {"192.0.2.1", "192.0.2.3"}
    assert state.data["ssh_failures"]["192.0.2.1"] == [100.0, 300.0]


def test_ssh_failure_window_prunes_old_entries(tmp_path):
    state = StateStore(tmp_path)
    state.add_ssh_failure("192.0.2.1", 100.0, window=300)
    count = state.add_ssh_failure("192.0.2.1", 500.0, window=300)

    assert count == 1
    assert state.data["ssh_failures"]["192.0.2.1"] == [500.0]


def test_ssh_failure_replaces_non_list_history(tmp_path):
    state = StateStore(tmp_path)
    state.data["ssh_failures"]["192.0.2.1"] = "invalid"

    count = state.add_ssh_failure("192.0.2.1", 100.0, window=300)

    assert count == 1
    assert state.data["ssh_failures"]["192.0.2.1"] == [100.0]


def test_ssh_failure_persistence_cadence(tmp_path, monkeypatch):
    clock = _storage(monkeypatch, monotonic=100.0)
    state = StateStore(
        tmp_path,
        ssh_failure_tracked_ips_max=10,
        ssh_failure_persist_threshold=3,
    )
    save = Mock()
    monkeypatch.setattr(state, "save", save)

    state.add_ssh_failure("192.0.2.1", 1.0, window=300)
    save.assert_called_once()

    state.add_ssh_failure("192.0.2.1", 2.0, window=300)
    save.assert_called_once()

    state.add_ssh_failure("192.0.2.1", 3.0, window=300)
    assert save.call_count == 2

    state.add_ssh_failure("192.0.2.1", 4.0, window=300)
    assert save.call_count == 2

    clock["monotonic"] = 116.0
    state.add_ssh_failure("192.0.2.1", 5.0, window=300)
    assert save.call_count == 3


def test_clear_ssh_failures_removes_and_persists_only_when_present(tmp_path, monkeypatch):
    state = StateStore(tmp_path)
    state.add_ssh_failure("192.0.2.1", 100.0, window=300)
    state.clear_ssh_failures("192.0.2.1")

    assert "192.0.2.1" not in state.data["ssh_failures"]
    assert "192.0.2.1" not in StateStore(tmp_path).data["ssh_failures"]

    save = Mock()
    monkeypatch.setattr(state, "save", save)
    state.clear_ssh_failures("192.0.2.1")
    save.assert_not_called()


def test_set_health_active_returns_previous_state_and_persists(tmp_path):
    state = StateStore(tmp_path)

    assert state.set_health_active("disk", True) is False
    assert state.set_health_active("disk", True) is True
    assert state.set_health_active("disk", False) is True

    reloaded = StateStore(tmp_path)
    assert reloaded.data["health_active"]["disk"] is False


def test_state_persists_across_store_instances(tmp_path):
    state = StateStore(tmp_path)
    state.update_file_cursor("/var/log/auth.log", 99, 1234)
    state.set_health_active("memory", True)
    state.add_ssh_failure("192.0.2.5", 500.0, window=300)
    state.mark_alert_sent("ssh-burst", cooldown=60)

    reloaded = StateStore(tmp_path)

    assert reloaded.file_cursor("/var/log/auth.log") == {"inode": 99, "offset": 1234}
    assert reloaded.data["health_active"]["memory"] is True
    assert reloaded.data["ssh_failures"]["192.0.2.5"] == [500.0]
    assert "ssh-burst" in reloaded.data["alerts"]


def test_invalid_state_file_loads_empty_state(tmp_path):
    (tmp_path / "state.json").write_text("not-json")

    state = StateStore(tmp_path)

    assert state.data == {
        "files": {},
        "alerts": {},
        "health_active": {},
        "ssh_failures": {},
        "journal": {},
    }
