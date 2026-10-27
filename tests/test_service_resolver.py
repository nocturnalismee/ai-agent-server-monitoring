import subprocess

import pytest

from server_agent.detectors import services as services_module
from server_agent.detectors.services import ServiceResolver


class FakeLogger:
    def debug(self, *args, **kwargs):
        pass


@pytest.fixture(autouse=True)
def reset_paths(monkeypatch):
    monkeypatch.setattr(services_module.os.path, "exists", lambda path: False)


def _show(stdout="", returncode=0):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="")


def test_unit_file_hit_returns_canonical_unit(monkeypatch):
    monkeypatch.setattr(
        services_module.os.path,
        "exists",
        lambda path: path.endswith("/etc/systemd/system/sshd.service"),
    )
    resolved = ServiceResolver().resolve("ssh")
    assert resolved.installed is True
    assert resolved.unit == "sshd.service"
    assert resolved.state == "installed"


def test_systemctl_show_resolves_alias(monkeypatch):
    monkeypatch.setattr(
        services_module.subprocess,
        "run",
        lambda *args, **kwargs: _show("Id=ssh.service\nLoadState=loaded\n"),
    )
    resolved = ServiceResolver().resolve("sshd")
    assert resolved.installed is True
    assert resolved.unit == "ssh.service"


def test_not_found_is_not_cached(monkeypatch):
    calls = []

    def fake_run(*args, **kwargs):
        calls.append(args)
        return _show("LoadState=not-found\n")

    monkeypatch.setattr(services_module.subprocess, "run", fake_run)
    resolver = ServiceResolver()
    assert resolver.resolve("missing").state == "not-found"
    assert resolver.resolve("missing").state == "not-found"
    assert len(calls) >= 2


def test_installed_result_is_cached(monkeypatch):
    calls = []

    def fake_run(*args, **kwargs):
        calls.append(args)
        return _show("Id=nginx.service\nLoadState=loaded\n")

    monkeypatch.setattr(services_module.subprocess, "run", fake_run)
    resolver = ServiceResolver()
    assert resolver.resolve("nginx").installed is True
    before = len(calls)
    assert resolver.resolve("nginx").installed is True
    assert len(calls) == before


def test_missing_systemctl_returns_unknown(monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("systemctl")

    monkeypatch.setattr(services_module.subprocess, "run", fake_run)
    assert ServiceResolver().resolve("nginx").state == "unknown"


def test_timeout_returns_unknown(monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="systemctl", timeout=2)

    monkeypatch.setattr(services_module.subprocess, "run", fake_run)
    assert ServiceResolver().resolve("nginx").state == "unknown"
