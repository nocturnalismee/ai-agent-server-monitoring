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


def _no_probe(monkeypatch):
    exists_calls = []
    run_calls = []

    def fake_exists(path):
        exists_calls.append(path)
        return True

    def fake_run(*args, **kwargs):
        run_calls.append(args)
        return _show("Id=evil.service\nLoadState=loaded\n")

    monkeypatch.setattr(services_module.os.path, "exists", fake_exists)
    monkeypatch.setattr(services_module.subprocess, "run", fake_run)
    return exists_calls, run_calls


def test_traversal_name_is_rejected_without_probing(monkeypatch):
    exists_calls, run_calls = _no_probe(monkeypatch)
    resolved = ServiceResolver().resolve("../../tmp/evil")
    assert resolved.installed is False
    assert resolved.state == "not-found"
    assert exists_calls == []
    assert run_calls == []


def test_names_with_space_or_slash_are_rejected_without_probing(monkeypatch):
    exists_calls, run_calls = _no_probe(monkeypatch)
    resolver = ServiceResolver()
    assert resolver.resolve("nginx service").state == "not-found"
    assert resolver.resolve("nginx/service").state == "not-found"
    assert exists_calls == []
    assert run_calls == []


def test_non_string_name_is_rejected_without_probing(monkeypatch):
    exists_calls, run_calls = _no_probe(monkeypatch)
    resolved = ServiceResolver().resolve(None)
    assert resolved.installed is False
    assert resolved.state == "not-found"
    assert exists_calls == []
    assert run_calls == []


def test_valid_suffixed_name_still_resolves(monkeypatch):
    monkeypatch.setattr(
        services_module.subprocess,
        "run",
        lambda *args, **kwargs: _show("Id=nginx.service\nLoadState=loaded\n"),
    )
    resolved = ServiceResolver().resolve("nginx.service")
    assert resolved.installed is True
    assert resolved.unit == "nginx.service"
    assert resolved.state == "installed"
