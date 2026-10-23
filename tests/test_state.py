from server_agent.state import StateStore


def test_ssh_failure_tracking_is_bounded_by_source_ip(tmp_path):
    state = StateStore(tmp_path, ssh_failure_tracked_ips_max=2, ssh_failure_persist_threshold=3)
    state.add_ssh_failure("192.0.2.1", 100.0, 300)
    state.add_ssh_failure("192.0.2.2", 101.0, 300)
    state.add_ssh_failure("192.0.2.3", 102.0, 300)

    failures = state.data["ssh_failures"]
    assert len(failures) == 2
    assert "192.0.2.1" not in failures
    assert "192.0.2.3" in failures


def test_journal_cursor_persistence(tmp_path):
    state = StateStore(tmp_path)
    assert state.journal_cursor("kernel") is None
    state.update_journal_cursor("kernel", "s=123456789;i=abc")
    assert state.journal_cursor("kernel") == "s=123456789;i=abc"

    # Reload from disk
    reloaded = StateStore(tmp_path)
    assert reloaded.journal_cursor("kernel") == "s=123456789;i=abc"
