from server_agent.monitors.ssh import FAIL_RE, SUCCESS_RE


def test_success():
    line = "sshd[123]: Accepted publickey for ubuntu from 203.0.113.5 port 55422 ssh2"
    m = SUCCESS_RE.search(line)
    assert m
    assert m.group("user") == "ubuntu"
    assert m.group("ip") == "203.0.113.5"

def test_failure():
    line = "sshd[123]: Failed password for invalid user admin from 198.51.100.7 port 4444 ssh2"
    m = FAIL_RE.search(line)
    assert m
    assert m.group("ip") == "198.51.100.7"
