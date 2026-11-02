import hashlib
import json
from types import SimpleNamespace

import server_agent.core.spool as spool_module
from server_agent.core.models import Incident
from server_agent.core.spool import IncidentSpool


class _Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def time(self):
        return self.now


def _spool(tmp_path, monkeypatch, max_entries=200, max_attempts=5):
    clock = _Clock()
    monkeypatch.setattr(
        spool_module, "time", SimpleNamespace(time=clock.time)
    )
    return IncidentSpool(
        tmp_path, max_entries=max_entries, max_attempts=max_attempts
    ), clock


def _incident(fingerprint="fp:1", summary="summary"):
    return Incident(
        kind="health",
        severity="WARNING",
        title="title",
        summary=summary,
        fingerprint=fingerprint,
    )


def _key(fingerprint):
    return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:16]


def _read_entry(spool, key):
    return json.loads((spool.directory / f"{key}.json").read_text())


def test_add_stores_payload_and_due_returns_it(tmp_path, monkeypatch):
    spool, clock = _spool(tmp_path, monkeypatch)

    spool.add(_incident())

    entries = spool.due()
    assert len(entries) == 1
    key, incident, attempts = entries[0]
    assert key == _key("fp:1")
    assert incident["fingerprint"] == "fp:1"
    assert incident["summary"] == "summary"
    assert attempts == 0

    stored = _read_entry(spool, key)
    assert stored["incident"]["fingerprint"] == "fp:1"
    assert stored["attempts"] == 0
    assert stored["created_at"] == clock.now
    assert stored["next_attempt_at"] == clock.now


def test_add_sanitizes_secrets_before_storing(tmp_path, monkeypatch):
    spool, _ = _spool(tmp_path, monkeypatch)

    spool.add(_incident(summary="connection password=supersecret"))

    key = _key("fp:1")
    raw = (spool.directory / f"{key}.json").read_text()
    stored = _read_entry(spool, key)

    assert "supersecret" not in raw
    assert "[REDACTED]" in stored["incident"]["summary"]


def test_add_replaces_existing_entry_for_same_fingerprint(tmp_path, monkeypatch):
    spool, _ = _spool(tmp_path, monkeypatch)

    spool.add(_incident(summary="first"))
    spool.add(_incident(summary="second"))

    entries = spool.due()
    assert len(entries) == 1
    assert entries[0][1]["summary"] == "second"


def test_repeated_add_preserves_attempts_and_backoff(tmp_path, monkeypatch):
    spool, clock = _spool(tmp_path, monkeypatch)
    spool.add(_incident())
    key = _key("fp:1")
    spool.mark_attempt(key)
    before = _read_entry(spool, key)

    clock.now += 10
    spool.add(_incident(summary="replacement"))
    after = _read_entry(spool, key)

    assert after["incident"]["summary"] == "replacement"
    assert after["attempts"] == before["attempts"] == 1
    assert after["created_at"] == before["created_at"]
    assert after["next_attempt_at"] == before["next_attempt_at"]


def test_mark_attempt_applies_exponential_backoff(tmp_path, monkeypatch):
    spool, clock = _spool(tmp_path, monkeypatch)
    spool.add(_incident())
    key = _key("fp:1")

    spool.mark_attempt(key)

    stored = _read_entry(spool, key)
    assert stored["attempts"] == 1
    assert stored["next_attempt_at"] == clock.now + 60

    assert spool.due(now=clock.now + 59) == []
    assert len(spool.due(now=clock.now + 60)) == 1

    clock.now += 60
    spool.mark_attempt(key)
    stored = _read_entry(spool, key)
    assert stored["attempts"] == 2
    assert stored["next_attempt_at"] == clock.now + 120


def test_mark_attempt_removes_entry_after_max_attempts(tmp_path, monkeypatch):
    spool, clock = _spool(tmp_path, monkeypatch, max_attempts=3)
    spool.add(_incident())
    key = _key("fp:1")

    spool.mark_attempt(key)
    spool.mark_attempt(key)
    assert len(spool.due(now=clock.now + 10000)) == 1

    spool.mark_attempt(key)

    assert spool.due(now=clock.now + 10000) == []
    assert not (spool.directory / f"{key}.json").exists()


def test_remove_deletes_entry(tmp_path, monkeypatch):
    spool, _ = _spool(tmp_path, monkeypatch)
    spool.add(_incident())

    spool.remove(_key("fp:1"))

    assert spool.due() == []
    assert not (spool.directory / f"{_key('fp:1')}.json").exists()


def test_spool_is_bounded_and_evicts_oldest_entry(tmp_path, monkeypatch):
    spool, clock = _spool(tmp_path, monkeypatch, max_entries=2)

    spool.add(_incident("fp:old"))
    clock.now += 1
    spool.add(_incident("fp:middle"))
    clock.now += 1
    spool.add(_incident("fp:new"))

    keys = {entry[0] for entry in spool.due(now=clock.now + 10000)}
    assert _key("fp:old") not in keys
    assert keys == {_key("fp:middle"), _key("fp:new")}


def test_corrupt_entries_are_ignored_and_removed(tmp_path, monkeypatch):
    spool, _ = _spool(tmp_path, monkeypatch)
    spool.directory.mkdir(parents=True, exist_ok=True)
    corrupt = spool.directory / "deadbeefdeadbeef.json"
    corrupt.write_text("{not-json")
    spool.add(_incident())

    entries = spool.due()

    assert [entry[1]["fingerprint"] for entry in entries] == ["fp:1"]
    assert not corrupt.exists()
