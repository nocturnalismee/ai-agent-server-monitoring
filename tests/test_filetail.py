import logging

from server_agent.filetail import FileTailer
from server_agent.state import StateStore


def test_tailer_consumes_oversized_physical_line_without_retaining_it(tmp_path):
    log_path = tmp_path / "error.log"
    log_path.write_text("x" * 100 + "\nnext line\n")
    state = StateStore(tmp_path / "state")
    tailer = FileTailer(state, logging.getLogger(__name__))

    lines = tailer.read_new_lines(
        str(log_path), first_start_at_end=False, max_lines=2, max_line_chars=32
    )

    assert lines == ["x" * 32 + " [truncated]\n", "next line\n"]


def test_safe_path_exists_handles_missing_and_permission_errors(tmp_path, monkeypatch):
    from server_agent.filetail import safe_path_exists

    real_file = tmp_path / "test.log"
    real_file.write_text("hello")

    assert safe_path_exists(str(real_file)) is True
    assert safe_path_exists(str(tmp_path / "nonexistent.log")) is False
    assert safe_path_exists("") is False

    # Simulate PermissionError on os.path.exists (such as non-traversable parent dir on Python 3.12)
    def mock_exists_raising_permission(_):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr("os.path.exists", mock_exists_raising_permission)
    assert safe_path_exists(str(real_file)) is False
