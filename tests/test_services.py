"""Tests for systemd service detection."""

import subprocess
from types import SimpleNamespace

import pytest

from server_agent.detectors import services as services_module
from server_agent.detectors.services import ServiceDetector


class FakePath:
    existing = set()

    def __init__(self, value):
        self.value = str(value)

    def exists(self):
        return self.value in FakePath.existing


@pytest.fixture(autouse=True)
def _patch_paths(monkeypatch):
    FakePath.existing = set()
    monkeypatch.setattr(services_module, "Path", FakePath)


def _result(stdout="", stderr="", returncode=0):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_empty_candidates_returns_empty(monkeypatch):
    calls = []
    monkeypatch.setattr(
        services_module.subprocess, "run", lambda *a, **k: calls.append(a)
    )

    assert ServiceDetector().filter_installed_services([]) == []
    assert calls == []


def test_blank_candidates_are_skipped(monkeypatch):
    calls = []
    monkeypatch.setattr(
        services_module.subprocess, "run", lambda *a, **k: calls.append(a)
    )

    assert ServiceDetector().filter_installed_services(["", "   "]) == []
    assert calls == []


def test_existing_unit_file_is_installed_without_systemctl(monkeypatch):
    FakePath.existing = {"/etc/systemd/system/nginx.service"}
    calls = []
    monkeypatch.setattr(
        services_module.subprocess, "run", lambda *a, **k: calls.append(a)
    )

    assert ServiceDetector().filter_installed_services(["nginx"]) == ["nginx"]
    assert calls == []


def test_service_suffix_is_not_doubled(monkeypatch):
    FakePath.existing = {"/etc/systemd/system/nginx.service"}
    monkeypatch.setattr(services_module.subprocess, "run", lambda *a, **k: None)

    assert ServiceDetector().filter_installed_services(["nginx.service"]) == [
        "nginx.service"
    ]


def test_not_found_service_is_skipped_and_logged(monkeypatch):
    monkeypatch.setattr(
        services_module.subprocess,
        "run",
        lambda *a, **k: _result(
            stderr="Unit nginx.service could not be found.", returncode=1
        ),
    )
    logged = []
    logger = SimpleNamespace(debug=lambda *a, **k: logged.append(a))

    assert ServiceDetector(logger).filter_installed_services(["nginx"]) == []
    assert logged


def test_active_service_is_kept(monkeypatch):
    monkeypatch.setattr(
        services_module.subprocess,
        "run",
        lambda *a, **k: _result(stdout="active\n"),
    )

    assert ServiceDetector().filter_installed_services(["nginx"]) == ["nginx"]


def test_missing_systemctl_is_conservative(monkeypatch):
    def _raise(*args, **kwargs):
        raise FileNotFoundError("systemctl")

    monkeypatch.setattr(services_module.subprocess, "run", _raise)

    assert ServiceDetector().filter_installed_services(["nginx"]) == ["nginx"]


def test_timeout_is_conservative(monkeypatch):
    def _raise(*args, **kwargs):
        raise subprocess.TimeoutExpired("systemctl", 2)

    monkeypatch.setattr(services_module.subprocess, "run", _raise)

    assert ServiceDetector().filter_installed_services(["nginx"]) == ["nginx"]


def test_installed_result_is_cached(monkeypatch):
    monkeypatch.setattr(
        services_module.subprocess,
        "run",
        lambda *a, **k: _result(stdout="active"),
    )
    detector = ServiceDetector()

    assert detector._is_service_installed("nginx") is True

    def _unexpected(*args, **kwargs):
        raise AssertionError("systemctl should not be called again")

    monkeypatch.setattr(services_module.subprocess, "run", _unexpected)
    assert detector._is_service_installed("nginx") is True
