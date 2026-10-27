# Service Monitoring Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the fragile flat service watch list with alias-aware, per-panel required/optional service profiles that are configurable from the environment and evaluated with anti-flap protection.

**Architecture:** A new `service_profiles` module owns built-in profiles, alias groups, and env precedence. A `ServiceResolver` maps configured names to real systemd units by probing unit files and `systemctl show`. `HealthMonitor` evaluates required/optional targets with consecutive-failure counters persisted in `StateStore`, emits richer incidents carrying the resolved unit, and `EvidenceCollector` uses that unit for `journalctl` plus `systemctl status`.

**Tech Stack:** Python 3.9+ (stdlib only at runtime), pytest, ruff, bash installer, systemd.

**Spec:** `docs/superpowers/specs/2026-10-27-service-monitoring-design.md`

## Global Constraints

- Runtime dependencies stay `psutil==7.0.0` and `python-dotenv==1.2.2`; do not add third-party packages.
- Python 3.9 compatibility: use `from __future__ import annotations` and `typing.List/Dict/Tuple/Optional` in runtime-evaluated positions.
- Line length 100; ruff must stay clean (`python -m ruff check .`).
- The agent remains read-only: never start, stop, restart, enable, or disable services.
- Backward compatibility: legacy `SERVICES` non-empty continues to override everything and keeps `AUTO_DETECT_SERVICES` filtering.
- New env keys: `SERVICE_PROFILE` (default `auto`), `SERVICES_REQUIRED`, `SERVICES_OPTIONAL`, `SERVICE_FAILURE_THRESHOLD` (default `2`).
- Profile names: `auto`, `none`, `standalone`, `cpanel`, `cyberpanel`, `aapanel`, `plesk`, `directadmin`, `hestiacp`, `cloudpanel`, `runcloud`.
- Alias groups: `ssh/sshd`, `apache2/httpd/apache`, `mysql/mariadb/mysqld`, `exim/exim4`, `named/bind9/named-chroot`.
- Unit names must match `^[a-zA-Z0-9_@.:-]+$`.
- Every task ends with `python -m ruff check .` clean and its targeted pytest passing.

---

## File Structure

- Create `server_agent/detectors/service_profiles.py` — profiles, alias groups, profile selection, env-precedence target resolution.
- Modify `server_agent/detectors/services.py` — add `ResolvedService` and `ServiceResolver` (keep `ServiceDetector` for legacy filtering).
- Modify `server_agent/core/config.py` — new fields, unit-name validation, profile allowlist, required/optional overlap check.
- Modify `server_agent/core/state.py` — `service_failures` storage and counter methods.
- Modify `server_agent/monitors/health.py` — targets from profiles, alias resolution, required/optional severity, failure threshold, recovery.
- Modify `server_agent/collectors/evidence.py` — service evidence by resolved unit plus `systemctl status`.
- Modify `server_agent/agent.py` — pass panel to `HealthMonitor`; `--check-config` prints the resolved service plan.
- Modify `install.sh` — stop writing the active-only `SERVICES` snapshot; write `SERVICE_PROFILE=auto`; update `--print-platform`.
- Modify `.env.example`, `README.md` — document the new behavior.
- Create `tests/test_service_profiles.py`, `tests/test_service_resolver.py`.
- Modify `tests/test_config_extra.py`, `tests/test_state_extra.py`, `tests/test_health_monitor.py`, `tests/test_evidence_dispatch.py`, `tests/test_agent_main.py`.

---

### Task 1: Service profiles and target resolution

**Files:**
- Create: `server_agent/detectors/service_profiles.py`
- Test: `tests/test_service_profiles.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `PROFILES: Dict[str, ServiceProfile]`
  - `PROFILE_NAMES: FrozenSet[str]`
  - `ALIAS_GROUPS: Tuple[Tuple[str, ...], ...]`
  - `panel_to_profile(panel: Optional[str]) -> str`
  - `profile_name(profile: str, panel: Optional[str]) -> str`
  - `alias_candidates(name: str) -> List[str]`
  - `resolve_targets(profile: str, panel: Optional[str], legacy_services: Sequence[str] = (), required_override: Sequence[str] = (), optional_override: Sequence[str] = ()) -> Tuple[List[str], List[str]]`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_service_profiles.py
from server_agent.detectors.service_profiles import (
    alias_candidates,
    panel_to_profile,
    profile_name,
    resolve_targets,
)


def test_auto_follows_detected_panel():
    assert profile_name("auto", "cPanel/WHM") == "cpanel"
    assert profile_name("auto", "CyberPanel") == "cyberpanel"
    assert profile_name("auto", "HestiaCP") == "hestiacp"
    assert profile_name("auto", None) == "standalone"


def test_explicit_profile_wins_over_panel():
    assert profile_name("runcloud", "cPanel/WHM") == "runcloud"


def test_none_profile_has_no_targets():
    required, optional = resolve_targets("none", None)
    assert required == []
    assert optional == []


def test_standalone_defaults():
    required, optional = resolve_targets("standalone", None)
    assert required == ["ssh"]
    assert "nginx" in optional


def test_cpanel_defaults():
    required, optional = resolve_targets("auto", "cPanel/WHM")
    assert required == ["cpanel", "mysql", "exim", "dovecot"]
    assert "named" in optional


def test_legacy_services_override_profile_and_clear_optional():
    required, optional = resolve_targets(
        "auto", "cPanel/WHM", legacy_services=["nginx", "mariadb", "nginx"]
    )
    assert required == ["nginx", "mariadb"]
    assert optional == []


def test_required_override_replaces_required_but_keeps_profile_optional():
    required, optional = resolve_targets(
        "cpanel", None, required_override=["httpd", "mysql"]
    )
    assert required == ["httpd", "mysql"]
    assert optional == ["named"] or "named" in optional


def test_optional_override_replaces_optional_but_keeps_profile_required():
    required, optional = resolve_targets(
        "cpanel", None, optional_override=["redis"]
    )
    assert required == ["cpanel", "mysql", "exim", "dovecot"]
    assert optional == ["redis"]


def test_required_wins_over_optional_duplicate():
    required, optional = resolve_targets(
        "none", None, required_override=["nginx"], optional_override=["nginx", "redis"]
    )
    assert required == ["nginx"]
    assert optional == ["redis"]


def test_alias_candidates_and_service_suffix():
    assert alias_candidates("sshd") == ["ssh", "sshd"]
    assert alias_candidates("httpd") == ["apache2", "httpd", "apache"]
    assert alias_candidates("redis.service") == ["redis"]


def test_panel_to_profile_unknown_is_standalone():
    assert panel_to_profile("Some Unknown Panel") == "standalone"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_service_profiles.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'server_agent.detectors.service_profiles'`

- [ ] **Step 3: Implement the module**

```python
"""Per-panel systemd service profiles and environment override resolution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class ServiceProfile:
    required: Tuple[str, ...] = ()
    optional: Tuple[str, ...] = ()


PROFILES: Dict[str, ServiceProfile] = {
    "standalone": ServiceProfile(
        ("ssh",), ("nginx", "apache2", "httpd", "mysql", "redis", "docker")
    ),
    "cpanel": ServiceProfile(
        ("cpanel", "mysql", "exim", "dovecot"),
        (
            "named",
            "httpd",
            "lsws",
            "cphulkd",
            "pure-ftpd",
            "clamd",
            "spamd",
            "redis",
            "php-fpm",
        ),
    ),
    "cyberpanel": ServiceProfile(
        ("lscpd", "lsws", "mariadb"),
        ("postfix", "pure-ftpd", "dovecot", "powerdns", "redis", "php-fpm"),
    ),
    "aapanel": ServiceProfile(
        ("bt", "mysql"),
        ("nginx", "httpd", "apache2", "php-fpm", "redis", "pure-ftpd", "postgresql"),
    ),
    "plesk": ServiceProfile(
        ("sw-cp-server", "sw-engine", "psa"),
        ("nginx", "apache2", "httpd", "postfix", "dovecot", "mysql", "redis", "php-fpm"),
    ),
    "directadmin": ServiceProfile(
        ("directadmin",),
        ("httpd", "nginx", "apache2", "exim", "dovecot", "mysql", "php-fpm", "redis"),
    ),
    "hestiacp": ServiceProfile(
        ("hestia",),
        ("nginx", "apache2", "exim", "dovecot", "mysql", "named", "vsftpd", "php-fpm", "redis"),
    ),
    "cloudpanel": ServiceProfile(("clp-nginx", "clp-php-fpm"), ("mysql", "redis")),
    "runcloud": ServiceProfile(("nginx",), ("php-fpm", "mysql", "redis")),
    "none": ServiceProfile(),
}

PROFILE_NAMES: FrozenSet[str] = frozenset({"auto", *PROFILES})

ALIAS_GROUPS: Tuple[Tuple[str, ...], ...] = (
    ("ssh", "sshd"),
    ("apache2", "httpd", "apache"),
    ("mysql", "mariadb", "mysqld"),
    ("exim", "exim4"),
    ("named", "bind9", "named-chroot"),
)

_PANEL_TO_PROFILE = (
    ("cpanel", "cpanel"),
    ("whm", "cpanel"),
    ("cyberpanel", "cyberpanel"),
    ("aapanel", "aapanel"),
    ("baota", "aapanel"),
    ("plesk", "plesk"),
    ("directadmin", "directadmin"),
    ("hestiacp", "hestiacp"),
    ("vestacp", "hestiacp"),
    ("cloudpanel", "cloudpanel"),
    ("runcloud", "runcloud"),
)


def panel_to_profile(panel: Optional[str]) -> str:
    if not panel:
        return "standalone"
    key = panel.strip().lower()
    for token, name in _PANEL_TO_PROFILE:
        if token in key:
            return name
    return "standalone"


def profile_name(profile: str, panel: Optional[str]) -> str:
    name = (profile or "auto").strip().lower()
    if name == "auto":
        return panel_to_profile(panel)
    return name


def alias_candidates(name: str) -> List[str]:
    base = (name or "").strip()
    lowered = base.lower()
    if lowered.endswith(".service"):
        lowered = lowered[: -len(".service")]
    for group in ALIAS_GROUPS:
        if lowered in group:
            return list(group)
    return [base]


def _clean(values: Iterable[str]) -> List[str]:
    seen = set()
    cleaned: List[str] = []
    for raw in values:
        name = str(raw).strip()
        if name.lower().endswith(".service"):
            name = name[: -len(".service")]
        if not name or name in seen:
            continue
        seen.add(name)
        cleaned.append(name)
    return cleaned


def resolve_targets(
    profile: str,
    panel: Optional[str],
    legacy_services: Sequence[str] = (),
    required_override: Sequence[str] = (),
    optional_override: Sequence[str] = (),
) -> Tuple[List[str], List[str]]:
    legacy = _clean(legacy_services)
    if legacy:
        return legacy, []

    chosen = PROFILES.get(profile_name(profile, panel), ServiceProfile())
    required_override = _clean(required_override)
    optional_override = _clean(optional_override)
    required = required_override or list(chosen.required)
    optional = optional_override or list(chosen.optional)
    required_set = set(required)
    optional = [name for name in optional if name not in required_set]
    return required, optional
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_service_profiles.py -q`
Expected: PASS (11 passed)

- [ ] **Step 5: Ruff and commit**

Run: `python -m ruff check .`
Expected: `All checks passed!`

```bash
git add server_agent/detectors/service_profiles.py tests/test_service_profiles.py
git commit -m "feat: add per-panel service profiles and target resolution"
```

---

### Task 2: Alias-aware ServiceResolver

**Files:**
- Modify: `server_agent/detectors/services.py`
- Test: `tests/test_service_resolver.py`

**Interfaces:**
- Consumes: `alias_candidates` from Task 1.
- Produces:
  - `@dataclass(frozen=True) class ResolvedService` with fields `name: str`, `unit: str`, `installed: bool`, `state: str` (`"installed" | "not-found" | "unknown"`).
  - `ServiceResolver(logger=None)` with `resolve(name: str) -> ResolvedService`.
  - `ServiceDetector` unchanged.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_service_resolver.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_service_resolver.py -q`
Expected: FAIL with `ImportError: cannot import name 'ServiceResolver'`

- [ ] **Step 3: Implement the resolver**

Add to `server_agent/detectors/services.py`:

```python
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

from .service_profiles import alias_candidates

_UNIT_RE = re.compile(r"^[a-zA-Z0-9_@.:-]+$")


@dataclass(frozen=True)
class ResolvedService:
    name: str
    unit: str
    installed: bool
    state: str


class ServiceResolver:
    SYSTEMD_DIRS = (
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    )

    def __init__(self, logger=None):
        self.logger = logger
        self._cache: Dict[str, ResolvedService] = {}

    def resolve(self, name: str) -> ResolvedService:
        cached = self._cache.get(name)
        if cached is not None and cached.installed:
            return cached

        candidates = alias_candidates(name)
        for candidate in candidates:
            unit = self._find_unit_file(candidate)
            if unit:
                result = ResolvedService(name, unit, True, "installed")
                self._cache[name] = result
                return result

        saw_unknown = False
        for candidate in candidates:
            state, unit = self._query_unit(candidate)
            if state == "unknown":
                saw_unknown = True
                continue
            if state == "installed":
                result = ResolvedService(name, unit, True, "installed")
                self._cache[name] = result
                return result

        if saw_unknown:
            return ResolvedService(name, candidates[0], False, "unknown")
        return ResolvedService(name, candidates[0], False, "not-found")

    def _find_unit_file(self, candidate: str) -> str:
        unit = candidate if candidate.endswith(".service") else f"{candidate}.service"
        for directory in self.SYSTEMD_DIRS:
            path = os.path.join(directory, unit)
            try:
                if os.path.exists(path):
                    return unit
            except (PermissionError, OSError):
                continue
        return ""

    def _query_unit(self, candidate: str) -> tuple:
        try:
            proc = subprocess.run(
                ["systemctl", "show", "-p", "Id", "-p", "LoadState", "--", candidate],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return "unknown", ""

        data: Dict[str, str] = {}
        for line in (proc.stdout or "").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                data[key.strip()] = value.strip()
        load_state = data.get("LoadState", "")
        if proc.returncode != 0 or not load_state or load_state == "not-found":
            return "not-found", ""
        return "installed", data.get("Id") or candidate
```

Keep the existing `ServiceDetector` class below it. `_UNIT_RE` will be used by the health monitor/evidence? Not here; remove it if unused to keep ruff clean. Do not add `_UNIT_RE` in this task if unused. Only add imports actually used: `os`, `subprocess`, `dataclass`, `Dict`, `Optional`, `alias_candidates`. `Path`, `List`, `Set` remain for `ServiceDetector`.

- [ ] **Step 4: Run tests and ruff**

Run: `python -m pytest tests/test_service_resolver.py -q`
Expected: PASS (6 passed)

Run: `python -m ruff check .`
Expected: `All checks passed!`

- [ ] **Step 5: Commit**

```bash
git add server_agent/detectors/services.py tests/test_service_resolver.py
git commit -m "feat: resolve systemd unit aliases during service discovery"
```

---

### Task 3: Config fields and validation

**Files:**
- Modify: `server_agent/core/config.py`
- Test: `tests/test_config_extra.py` (append)

**Interfaces:**
- Consumes: `PROFILE_NAMES` from Task 1.
- Produces: `Config.service_profile`, `Config.services_required`, `Config.services_optional`, `Config.service_failure_threshold`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_config_extra.py`:

```python
from server_agent.core.config import Config


def _cfg(**overrides):
    from dataclasses import replace

    return replace(Config(), **overrides)


def test_service_profile_accepts_known_profiles():
    for name in ("auto", "none", "cpanel", "runcloud"):
        _cfg(service_profile=name).validate()


def test_service_profile_rejects_unknown():
    with pytest.raises(ValueError, match="SERVICE_PROFILE"):
        _cfg(service_profile="bogus").validate()


def test_service_failure_threshold_bounds():
    for value in (1, 2, 10):
        _cfg(service_failure_threshold=value).validate()
    for value in (0, 11):
        with pytest.raises(ValueError, match="SERVICE_FAILURE_THRESHOLD"):
            _cfg(service_failure_threshold=value).validate()


def test_required_and_optional_overlap_is_rejected():
    with pytest.raises(ValueError, match="both required and optional"):
        _cfg(services_required=["nginx"], services_optional=["nginx"]).validate()


def test_invalid_service_unit_name_is_rejected():
    with pytest.raises(ValueError, match="invalid systemd unit name"):
        _cfg(services_required=["nginx; rm -rf /"]).validate()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_config_extra.py -q -k "service_profile or service_failure or overlap or invalid_service_unit"`
Expected: FAIL with `TypeError: __init__() got an unexpected keyword argument 'service_profile'`

- [ ] **Step 3: Implement config changes**

Add `import re` at the top of `server_agent/core/config.py` and:

```python
from ..detectors.service_profiles import PROFILE_NAMES

_SERVICE_UNIT_RE = re.compile(r"^[a-zA-Z0-9_@.:-]+$")
```

After the existing `services` and `alert_on_missing_service` fields add:

```python
    service_profile: str = os.getenv("SERVICE_PROFILE", "auto").strip().lower()
    services_required: List[str] = field(default_factory=lambda: _csv("SERVICES_REQUIRED"))
    services_optional: List[str] = field(default_factory=lambda: _csv("SERVICES_OPTIONAL"))
    service_failure_threshold: int = _int("SERVICE_FAILURE_THRESHOLD", 2)
```

Inside `validate()`, after the SSH tracked-IP check and before the web-log path checks:

```python
        if self.service_profile not in PROFILE_NAMES:
            errors.append(
                "SERVICE_PROFILE must be one of: " + ", ".join(sorted(PROFILE_NAMES))
            )
        if not 1 <= self.service_failure_threshold <= 10:
            errors.append("SERVICE_FAILURE_THRESHOLD must be between 1 and 10")
        required_names = {name.strip() for name in self.services_required if name.strip()}
        optional_names = {name.strip() for name in self.services_optional if name.strip()}
        overlap = sorted(required_names & optional_names)
        if overlap:
            errors.append(
                "Services cannot be both required and optional: " + ", ".join(overlap)
            )
        for label, values in (
            ("SERVICES", self.services),
            ("SERVICES_REQUIRED", self.services_required),
            ("SERVICES_OPTIONAL", self.services_optional),
        ):
            for value in values:
                name = value.strip()
                if name and not _SERVICE_UNIT_RE.match(name):
                    errors.append(f"{label} contains an invalid systemd unit name: {value}")
```

- [ ] **Step 4: Run tests and ruff**

Run: `python -m pytest tests/test_config_extra.py -q`
Expected: PASS (all existing tests plus the new ones)

Run: `python -m ruff check .`
Expected: `All checks passed!`

- [ ] **Step 5: Commit**

```bash
git add server_agent/core/config.py tests/test_config_extra.py
git commit -m "feat: add service profile configuration and validation"
```

---

### Task 4: Persist per-service failure counters

**Files:**
- Modify: `server_agent/core/state.py`
- Test: `tests/test_state_extra.py` (append)

**Interfaces:**
- Consumes: existing `StateStore` lock/`save()`.
- Produces:
  - `service_failure_count(key: str) -> int`
  - `increment_service_failure(key: str) -> int`
  - `clear_service_failure(key: str) -> None`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_state_extra.py`:

```python
def test_service_failure_counter_roundtrip(tmp_path):
    from server_agent.core.state import StateStore

    state = StateStore(tmp_path)
    key = "service:mysql"
    assert state.service_failure_count(key) == 0
    assert state.increment_service_failure(key) == 1
    assert state.increment_service_failure(key) == 2
    assert state.service_failure_count(key) == 2

    reloaded = StateStore(tmp_path)
    assert reloaded.service_failure_count(key) == 2

    reloaded.clear_service_failure(key)
    assert reloaded.service_failure_count(key) == 0
    assert StateStore(tmp_path).service_failure_count(key) == 0


def test_clear_missing_service_counter_is_a_noop(tmp_path):
    from server_agent.core.state import StateStore

    state = StateStore(tmp_path)
    state.clear_service_failure("service:absent")
    assert state.service_failure_count("service:absent") == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_state_extra.py -q -k service_failure`
Expected: FAIL with `AttributeError: 'StateStore' object has no attribute 'service_failure_count'`

- [ ] **Step 3: Implement state changes**

Add `"service_failures": {}` to the `empty` dict in `_load()`.

Add after `clear_ssh_failures`:

```python
    def service_failure_count(self, key: str) -> int:
        with self.lock:
            failures = self.data.setdefault("service_failures", {})
            try:
                return int(failures.get(key, 0))
            except (TypeError, ValueError):
                return 0

    def increment_service_failure(self, key: str) -> int:
        with self.lock:
            failures = self.data.setdefault("service_failures", {})
            try:
                count = int(failures.get(key, 0)) + 1
            except (TypeError, ValueError):
                count = 1
            failures[key] = count
            self.save()
            return count

    def clear_service_failure(self, key: str) -> None:
        with self.lock:
            failures = self.data.setdefault("service_failures", {})
            if key in failures:
                failures.pop(key)
                self.save()
```

- [ ] **Step 4: Run tests and ruff**

Run: `python -m pytest tests/test_state_extra.py -q`
Expected: PASS

Run: `python -m ruff check .`
Expected: `All checks passed!`

- [ ] **Step 5: Commit**

```bash
git add server_agent/core/state.py tests/test_state_extra.py
git commit -m "feat: persist consecutive service failure counters"
```

---

### Task 5: HealthMonitor required/optional evaluation

**Files:**
- Modify: `server_agent/monitors/health.py`
- Test: `tests/test_health_monitor.py` (append)

**Interfaces:**
- Consumes: `resolve_targets` (Task 1), `ServiceResolver`/`ResolvedService` (Task 2), `StateStore.service_failure_*` (Task 4), `Config.service_*` (Task 3).
- Produces: `HealthMonitor(config, state, logger, panel: Optional[str] = None)`; incidents with `details["unit"]`, `details["required"]`, `details["consecutive_failures"]`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_health_monitor.py`:

```python
from server_agent.detectors.services import ResolvedService


class FakeResolver:
    def __init__(self, mapping):
        self.mapping = mapping

    def resolve(self, name):
        return self.mapping[name]


def _service_monitor(monkeypatch, mapping, is_active):
    monitor = make_monitor()
    monitor.cfg.service_profile = "none"
    monitor.cfg.services_required = ["mysql"]
    monitor.cfg.services_optional = ["redis"]
    monitor.cfg.service_failure_threshold = 2
    monitor.cfg.alert_on_missing_service = False
    monitor.cfg.recovery_alerts = True
    monitor.resolver = FakeResolver(mapping)
    monkeypatch.setattr(
        monitor, "_service_state", lambda unit: is_active(unit)
    )
    return monitor


def test_required_missing_service_is_critical(monkeypatch):
    mapping = {
        "mysql": ResolvedService("mysql", "mysql.service", False, "not-found"),
        "redis": ResolvedService("redis", "redis.service", True, "installed"),
    }
    monitor = _service_monitor(monkeypatch, mapping, lambda unit: ("active", ""))
    incidents = monitor.collect_services()
    assert len(incidents) == 1
    assert incidents[0].severity == "CRITICAL"
    assert incidents[0].details["unit"] == "mysql.service"
    assert incidents[0].details["required"] is True


def test_optional_missing_service_is_skipped(monkeypatch):
    mapping = {
        "mysql": ResolvedService("mysql", "mysql.service", True, "installed"),
        "redis": ResolvedService("redis", "redis.service", False, "not-found"),
    }
    monitor = _service_monitor(monkeypatch, mapping, lambda unit: ("active", ""))
    assert monitor.collect_services() == []


def test_service_alert_waits_for_threshold(monkeypatch):
    mapping = {
        "mysql": ResolvedService("mysql", "mysql.service", True, "installed"),
        "redis": ResolvedService("redis", "redis.service", True, "installed"),
    }
    monitor = _service_monitor(monkeypatch, mapping, lambda unit: ("inactive", ""))
    assert monitor.collect_services() == []
    incidents = monitor.collect_services()
    assert len(incidents) == 1
    assert incidents[0].severity == "CRITICAL"
    assert incidents[0].details["consecutive_failures"] == 2


def test_failed_service_alerts_immediately(monkeypatch):
    mapping = {
        "mysql": ResolvedService("mysql", "mysql.service", True, "installed"),
        "redis": ResolvedService("redis", "redis.service", True, "installed"),
    }
    monitor = _service_monitor(monkeypatch, mapping, lambda unit: ("failed", "boom"))
    incidents = monitor.collect_services()
    assert len(incidents) == 1
    assert incidents[0].severity == "CRITICAL"
    assert incidents[0].details["state"] == "failed"


def test_optional_inactive_is_warning_at_threshold(monkeypatch):
    mapping = {
        "mysql": ResolvedService("mysql", "mysql.service", True, "installed"),
        "redis": ResolvedService("redis", "redis.service", True, "installed"),
    }
    monitor = _service_monitor(
        monkeypatch, mapping, lambda unit: ("inactive", "") if unit == "redis.service" else ("active", "")
    )
    assert monitor.collect_services() == []
    incidents = monitor.collect_services()
    assert len(incidents) == 1
    assert incidents[0].severity == "WARNING"
    assert incidents[0].details["required"] is False


def test_active_service_clears_counter_and_emits_recovery(monkeypatch):
    mapping = {
        "mysql": ResolvedService("mysql", "mysql.service", True, "installed"),
        "redis": ResolvedService("redis", "redis.service", True, "installed"),
    }
    monitor = _service_monitor(monkeypatch, mapping, lambda unit: ("failed", "boom"))
    monitor.collect_services()
    monitor._service_state = lambda unit: ("active", "")
    incidents = monitor.collect_services()
    assert len(incidents) == 1
    assert incidents[0].kind == "recovery"
    assert incidents[0].severity == "INFO"


def test_unknown_required_is_warning(monkeypatch):
    mapping = {
        "mysql": ResolvedService("mysql", "mysql.service", False, "unknown"),
        "redis": ResolvedService("redis", "redis.service", True, "installed"),
    }
    monitor = _service_monitor(monkeypatch, mapping, lambda unit: ("active", ""))
    incidents = monitor.collect_services()
    assert len(incidents) == 1
    assert incidents[0].severity == "WARNING"
    assert incidents[0].details["state"] == "unknown"
```

Add `collect_services()` to the production monitor, returning only service/recovery incidents; `collect()` will extend it.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_health_monitor.py -q -k "required_missing or optional_missing or waits_for_threshold or failed_service or optional_inactive or clears_counter or unknown_required"`
Expected: FAIL (no `resolver`/`collect_services`)

- [ ] **Step 3: Implement HealthMonitor changes**

At the top imports add:

```python
from typing import List, Optional, Tuple

from ..detectors.service_profiles import resolve_targets
from ..detectors.services import ResolvedService, ServiceResolver
```

Change the constructor signature and body:

```python
    def __init__(self, config, state, logger, panel: Optional[str] = None):
        self.cfg = config
        self.state = state
        self.log = logger
        self.panel = panel
        self.resolver = ServiceResolver(logger)
        legacy = list(config.services)
        if getattr(config, "auto_detect_services", True):
            legacy = ServiceDetector(logger).filter_installed_services(legacy)
        self.monitored_services = legacy
        psutil.cpu_percent(interval=None)
```

Replace the old `collect()` service loop with a call to `collect_services()`:

```python
    def collect_services(self) -> List[Incident]:
        incidents: List[Incident] = []
        targets = self._service_targets()
        resolved: List[Tuple[str, bool, ResolvedService]] = []
        by_unit = {}
        for name, required in targets:
            item = self.resolver.resolve(name)
            existing = by_unit.get(item.unit)
            if existing is not None and existing[1] and not required:
                continue
            by_unit[item.unit] = (name, required, item)
        resolved = list(by_unit.values())

        for name, required, item in resolved:
            if item.state == "not-found":
                if not required:
                    continue
                incidents.append(
                    self._service_incident(name, item.unit, "not-found", True, "", 0)
                )
                continue
            if item.state == "unknown":
                if required or getattr(self.cfg, "alert_on_missing_service", False):
                    incidents.append(
                        self._service_incident(
                            name,
                            item.unit,
                            "unknown",
                            required,
                            "",
                            0,
                            severity="WARNING",
                        )
                    )
                continue

            state, error = self._service_state(item.unit)
            key = f"service:{name}"
            if state == "active":
                self.state.clear_service_failure(key)
                was_problem = self.state.set_health_active(key, False)
                if was_problem and getattr(self.cfg, "recovery_alerts", True):
                    incidents.append(
                        Incident(
                            kind="recovery",
                            severity="INFO",
                            title=f"Service {name} recovered",
                            summary=f"Service {name} ({item.unit}) is active again.",
                            fingerprint=f"recovery:{key}",
                            details={"service": name, "unit": item.unit, "state": "active"},
                        )
                    )
                continue

            failures = self.state.increment_service_failure(key)
            threshold = getattr(self.cfg, "service_failure_threshold", 2)
            if state == "failed" or failures >= threshold:
                severity = "CRITICAL" if required else "WARNING"
                incidents.append(
                    self._service_incident(
                        name, item.unit, state, required, error, failures, severity
                    )
                )
        return incidents

    def _service_targets(self) -> List[Tuple[str, bool]]:
        legacy = list(getattr(self.cfg, "services", []) or [])
        if legacy and getattr(self.cfg, "auto_detect_services", True):
            legacy = ServiceDetector(self.log).filter_installed_services(legacy)
        required, optional = resolve_targets(
            getattr(self.cfg, "service_profile", "auto"),
            self.panel,
            legacy,
            getattr(self.cfg, "services_required", []) or [],
            getattr(self.cfg, "services_optional", []) or [],
        )
        return [(name, True) for name in required] + [(name, False) for name in optional]

    def _service_incident(
        self,
        name: str,
        unit: str,
        state: str,
        required: bool,
        error: str,
        failures: int,
        severity: str = "CRITICAL",
    ) -> Incident:
        key = f"service:{name}"
        self.state.set_health_active(key, True)
        if state == "not-found":
            title = f"Service {name} is not installed"
        elif state == "unknown":
            title = f"Service {name} state is unknown"
        else:
            title = f"Service {name} is not active"
        details = {
            "service": name,
            "unit": unit,
            "state": state,
            "required": required,
            "consecutive_failures": failures,
        }
        if error:
            details["error"] = error
        return Incident(
            kind="service",
            severity=severity,
            title=title,
            summary=f"Service {name} ({unit}) reported state '{state}'.",
            fingerprint=key,
            details=details,
        )
```

In `collect()`, replace the entire existing service `for service in self.monitored_services:` block with:

```python
        incidents.extend(self.collect_services())
```

Remove the now-unused `_service_state`? No — keep it; it is used. Ensure `_service_state` returns state from `systemctl is-active -- <unit>`.

- [ ] **Step 4: Run tests and ruff**

Run: `python -m pytest tests/test_health_monitor.py -q`
Expected: PASS (existing + 9 new)

Run: `python -m ruff check .`
Expected: `All checks passed!`

- [ ] **Step 5: Commit**

```bash
git add server_agent/monitors/health.py tests/test_health_monitor.py
git commit -m "feat: evaluate required/optional services with failure thresholds"
```

---

### Task 6: Service evidence by resolved unit

**Files:**
- Modify: `server_agent/collectors/evidence.py`
- Test: `tests/test_evidence_dispatch.py` (append)

**Interfaces:**
- Consumes: `incident.details["unit"]` from Task 5.
- Produces: `_collect_service_journal(service: str, unit: Optional[str] = None) -> str`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_evidence_dispatch.py`:

```python
def test_service_evidence_uses_resolved_unit(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "line-1\nline-2\n", "")

    monkeypatch.setattr(evidence_module.subprocess, "run", fake_run)
    collector = EvidenceCollector(max_lines=10)
    incident = Incident(
        kind="service",
        severity="CRITICAL",
        title="Service mysql is not active",
        summary="",
        fingerprint="service:mysql",
        details={"service": "mysql", "unit": "mariadb.service"},
    )
    text = collector.collect(incident)
    assert calls[0][:3] == ["journalctl", "-u", "mariadb.service"]
    assert calls[1][:2] == ["systemctl", "status"]
    assert "mariadb.service" in text
    assert "systemctl status mariadb.service" in text


def test_service_evidence_rejects_unsafe_unit(monkeypatch):
    calls = []
    monkeypatch.setattr(
        evidence_module.subprocess,
        "run",
        lambda command, **kwargs: calls.append(command),
    )
    collector = EvidenceCollector()
    incident = Incident(
        kind="service",
        severity="CRITICAL",
        title="bad",
        summary="",
        fingerprint="service:bad",
        details={"service": "mysql", "unit": "mysql; rm -rf /"},
    )
    assert collector.collect(incident) == ""
    assert calls == []


def test_service_evidence_falls_back_to_service_name(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "ok\n", "")

    monkeypatch.setattr(evidence_module.subprocess, "run", fake_run)
    collector = EvidenceCollector()
    incident = Incident(
        kind="service",
        severity="CRITICAL",
        title="Service nginx is not active",
        summary="",
        fingerprint="service:nginx",
        details={"service": "nginx"},
    )
    text = collector.collect(incident)
    assert calls[0][:3] == ["journalctl", "-u", "nginx"]
    assert "nginx" in text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_evidence_dispatch.py -q -k "resolved_unit or unsafe_unit or falls_back"`
Expected: FAIL (journalctl called without unit / unsafe unit accepted)

- [ ] **Step 3: Implement evidence changes**

Add `import re` and:

```python
_UNIT_RE = re.compile(r"^[a-zA-Z0-9_@.:-]+$")
```

Change the service dispatch:

```python
            if incident.kind == "service":
                unit = incident.details.get("unit")
                return self._collect_service_journal(
                    incident.details.get("service", ""), unit
                )
```

Replace `_collect_service_journal` with:

```python
    def _collect_service_journal(self, service: str, unit: str | None = None) -> str:
        target = unit or service
        if not target or not _UNIT_RE.match(target):
            return ""
        parts = []
        try:
            proc = subprocess.run(
                ["journalctl", "-u", target, "-n", str(self.max_lines), "--no-pager"],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            if proc.stdout.strip():
                parts.append(
                    f"--- journalctl -u {target} (last {self.max_lines} lines) ---\n"
                    f"{proc.stdout.strip()}"
                )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        try:
            proc = subprocess.run(
                ["systemctl", "status", "--no-pager", "-l", "--", target],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            output = (proc.stdout or proc.stderr or "").strip()
            if output:
                lines = output.splitlines()[: self.max_lines]
                parts.append(
                    f"--- systemctl status {target} ---\n" + "\n".join(lines)
                )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return "\n\n".join(parts)
```

Use `Optional[str]` instead of `str | None` to keep Python 3.9 runtime annotations safe (the module already imports `Optional` or add it).

- [ ] **Step 4: Run tests and ruff**

Run: `python -m pytest tests/test_evidence_dispatch.py -q`
Expected: PASS

Run: `python -m ruff check .`
Expected: `All checks passed!`

- [ ] **Step 5: Commit**

```bash
git add server_agent/collectors/evidence.py tests/test_evidence_dispatch.py
git commit -m "feat: collect service evidence from the resolved unit"
```

---

### Task 7: Agent wiring and `--check-config` service plan

**Files:**
- Modify: `server_agent/agent.py`
- Test: `tests/test_agent_main.py` (append)

**Interfaces:**
- Consumes: `resolve_targets`, `profile_name` (Task 1); `HealthMonitor(..., panel=...)` (Task 5); `ServiceDetector` (existing).
- Produces: `_print_service_plan(cfg) -> None`; `--check-config` prints profile/required/optional lines.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_agent_main.py`:

```python
def test_check_config_prints_service_plan(monkeypatch, capsys):
    cfg = _patch_config(
        monkeypatch,
        service_profile="cpanel",
        services_required=["httpd", "mysql"],
        services_optional=["redis"],
        auto_detect_environment=False,
    )
    _patch_agent(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["server_agent", "--check-config"])
    assert main() == 0
    out = capsys.readouterr().out
    assert "Configuration OK" in out
    assert "Service profile: cpanel (explicit)" in out
    assert "Required: httpd, mysql" in out
    assert "Optional: redis" in out


def test_check_config_auto_uses_detected_panel(monkeypatch, capsys):
    cfg = _patch_config(
        monkeypatch,
        service_profile="auto",
        services_required=[],
        services_optional=[],
        auto_detect_environment=True,
    )
    _patch_agent(monkeypatch)
    monkeypatch.setattr(
        agent_module,
        "EnvironmentDetector",
        lambda logger=None: SimpleNamespace(
            detect=lambda: SimpleNamespace(panel="cPanel/WHM")
        ),
    )
    monkeypatch.setattr(sys, "argv", ["server_agent", "--check-config"])
    assert main() == 0
    out = capsys.readouterr().out
    assert "Service profile: cpanel (auto)" in out
    assert "Required: cpanel, mysql, exim, dovecot" in out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_agent_main.py -q -k "service_plan or auto_uses"`
Expected: FAIL (no service plan output)

- [ ] **Step 3: Implement agent changes**

Add imports:

```python
from .detectors.service_profiles import profile_name, resolve_targets
from .detectors.services import ServiceDetector
```

Add `_print_service_plan` before `main()`:

```python
def _print_service_plan(cfg) -> None:
    panel = None
    if getattr(cfg, "auto_detect_environment", False):
        try:
            panel = EnvironmentDetector(None).detect().panel
        except Exception:
            panel = None
    legacy = list(cfg.services)
    if legacy and getattr(cfg, "auto_detect_services", True):
        legacy = ServiceDetector(None).filter_installed_services(legacy)
    required, optional = resolve_targets(
        cfg.service_profile,
        panel,
        legacy,
        cfg.services_required,
        cfg.services_optional,
    )
    mode = "auto" if cfg.service_profile == "auto" else "explicit"
    print(f"Service profile: {profile_name(cfg.service_profile, panel)} ({mode})")
    print("Required: " + (", ".join(required) if required else "(none)"))
    print("Optional: " + (", ".join(optional) if optional else "(none)"))
```

In `main()`, change the check-config branch:

```python
    if args.check_config:
        print("Configuration OK")
        _print_service_plan(cfg)
        return 0
```

In `Agent.__init__`, change the HealthMonitor construction to pass the detected panel:

```python
        self.health = HealthMonitor(
            cfg,
            self.state,
            self.log,
            panel=self.metadata.panel if self.metadata else None,
        )
```

- [ ] **Step 4: Run tests and ruff**

Run: `python -m pytest tests/test_agent_main.py -q`
Expected: PASS

Run: `python -m ruff check .`
Expected: `All checks passed!`

- [ ] **Step 5: Commit**

```bash
git add server_agent/agent.py tests/test_agent_main.py
git commit -m "feat: wire service profiles into the agent and check-config"
```

---

### Task 8: Installer and env template

**Files:**
- Modify: `install.sh`
- Modify: `.env.example`
- Test: `bash -n install.sh` (syntax) and manual `--print-platform`

**Interfaces:**
- Consumes: profile names from Task 1 for the printed hint.
- Produces: env file with `SERVICE_PROFILE=auto` and no active-only `SERVICES` snapshot.

- [ ] **Step 1: Update `install.sh`**

Replace the line that writes the legacy snapshot (currently `set_env_value SERVICES "$DEFAULT_SERVICES" "$env_file"`) with:

```bash
  set_env_value SERVICE_PROFILE "auto" "$env_file"
  if ! grep -q '^# Legacy override' "$env_file" 2>/dev/null; then
    printf '\n# Legacy override (optional, takes precedence over the profile):\n# SERVICES=nginx,mysql\n' >> "$env_file"
  fi
```

Update the `--print-platform` branch so it reports the new profile and does not claim an active-only snapshot. Use this text instead of the old SERVICES line:

```bash
    echo "service profile: auto (per-panel at runtime)"
    echo "service candidates : $DEFAULT_SERVICES"
```

Keep `resolve_default_services()` for this display only.

- [ ] **Step 2: Update `.env.example`**

Replace the existing `SERVICES=...` block with:

```dotenv
# Service monitoring profile. `auto` follows the detected control panel.
# Values: auto, none, standalone, cpanel, cyberpanel, aapanel, plesk,
#         directadmin, hestiacp, cloudpanel, runcloud
SERVICE_PROFILE=auto
# Optional explicit overrides (they take precedence over the profile).
# SERVICES_REQUIRED=cpanel,mysql,exim,dovecot
# SERVICES_OPTIONAL=named,redis
# Alerts only after this many consecutive non-active checks (failed alerts immediately).
SERVICE_FAILURE_THRESHOLD=2
# Legacy: a non-empty SERVICES list overrides the profile entirely.
# SERVICES=nginx,apache2,httpd,ssh,sshd,lshttpd,mysql
```

- [ ] **Step 3: Verify syntax**

Run: `bash -n install.sh`
Expected: no output (exit 0)

Run: `bash -n uninstall.sh`
Expected: no output (exit 0)

- [ ] **Step 4: Commit**

```bash
git add install.sh .env.example
git commit -m "feat: default installs to the auto service profile"
```

---

### Task 9: Documentation and final verification

**Files:**
- Modify: `README.md`
- Test: full suite

**Interfaces:**
- Consumes: all previous tasks.
- Produces: documented behavior and a green build.

- [ ] **Step 1: Add a Service Monitoring section to `README.md`**

Insert before `### SMTP Email` (or after the escalation section):

```markdown
### Service Monitoring

The agent watches a per-panel set of systemd services. The default
`SERVICE_PROFILE=auto` follows the detected panel:

| Profile | Required (alert if missing/inactive) | Optional (alert if installed but inactive) |
| :--- | :--- | :--- |
| standalone | ssh | nginx, apache2, httpd, mysql, redis, docker |
| cpanel | cpanel, mysql, exim, dovecot | named, httpd, lsws, cphulkd, pure-ftpd, clamd, spamd, redis, php-fpm |
| cyberpanel | lscpd, lsws, mariadb | postfix, pure-ftpd, dovecot, powerdns, redis, php-fpm |
| aapanel | bt, mysql | nginx, httpd, apache2, php-fpm, redis, pure-ftpd, postgresql |
| plesk | sw-cp-server, sw-engine, psa | nginx, apache2, httpd, postfix, dovecot, mysql, redis, php-fpm |
| directadmin | directadmin | httpd, nginx, apache2, exim, dovecot, mysql, php-fpm, redis |
| hestiacp | hestia | nginx, apache2, exim, dovecot, mysql, named, vsftpd, php-fpm, redis |
| cloudpanel | clp-nginx, clp-php-fpm | mysql, redis |
| runcloud | nginx | php-fpm, mysql, redis |

Override precedence (highest first):

1. `SERVICES` (legacy) — replaces the profile entirely and keeps
   `AUTO_DETECT_SERVICES` filtering.
2. `SERVICES_REQUIRED` — replaces the profile's required list.
3. `SERVICES_OPTIONAL` — replaces the profile's optional list.
4. `SERVICE_PROFILE` — `auto`, `none`, or an explicit profile name.

Common aliases are resolved automatically: `ssh`/`sshd`,
`apache2`/`httpd`/`apache`, `mysql`/`mariadb`/`mysqld`, `exim`/`exim4`,
`named`/`bind9`/`named-chroot`.

`SERVICE_FAILURE_THRESHOLD` (default `2`) requires this many consecutive
non-active checks before alerting; a `failed` unit alerts immediately.
`sudo -u server-agent /opt/server-ai-agent/venv/bin/python -m server_agent --check-config`
prints the final profile, required, and optional lists.
```

- [ ] **Step 2: Add config table rows**

After the `SERVICES` row (or near it) add:

```markdown
| `SERVICE_PROFILE` | `auto` | Per-panel service profile: `auto`, `none`, or a panel name. |
| `SERVICES_REQUIRED` | _(unset)_ | Overrides the profile's required service list. |
| `SERVICES_OPTIONAL` | _(unset)_ | Overrides the profile's optional service list. |
| `SERVICE_FAILURE_THRESHOLD` | `2` | Consecutive non-active checks before alerting (`failed` alerts immediately). |
```

Also document `SERVICE_PROFILE` in Troubleshooting: if a required panel
service is intentionally absent, move it to `SERVICES_OPTIONAL` or set
`SERVICE_PROFILE=none` and list services explicitly.

- [ ] **Step 3: Run the full verification**

Run: `python -m ruff check .`
Expected: `All checks passed!`

Run: `python -m pytest -q --cov=server_agent --cov-report=term-missing`
Expected: all tests pass; coverage at or above 55%.

Run: `bash -n install.sh && bash -n uninstall.sh`
Expected: no output (exit 0)

- [ ] **Step 4: Commit and push**

```bash
git add README.md
git commit -m "docs: document per-panel service monitoring"
git push origin main
```

---

## Self-Review

- **Spec coverage:** config (Task 3), profiles/precedence (Task 1), alias resolution (Task 2), health severity/threshold/recovery (Task 5), state persistence (Task 4), evidence (Task 6), CLI/installer (Tasks 7-8), docs (Task 9), tests throughout. Backward compatibility is preserved by keeping `SERVICES` and `AUTO_DETECT_SERVICES`.
- **Placeholder scan:** no TBD/TODO; each code step contains the implementation and each test step contains assertions.
- **Type consistency:** `ResolvedService.state` is `installed|not-found|unknown` everywhere; `collect_services()` returns `List[Incident]`; `resolve_targets` returns `(List[str], List[str])`; `_service_incident` signature is consistent in Task 5.
- **Python 3.9 note:** use `Optional[str]` in `evidence.py`; `from __future__ import annotations` is already present where needed.
