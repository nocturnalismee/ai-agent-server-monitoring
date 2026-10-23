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
