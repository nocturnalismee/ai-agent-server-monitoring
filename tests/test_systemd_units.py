"""Section-aware checks for the shipped systemd units."""

import configparser
from pathlib import Path

UNIT_DIR = Path(__file__).resolve().parents[1] / "systemd"
UNITS = ("server-ai-agent.service", "server-ai-agent-watchdog.service")


def _parse(name):
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.read(UNIT_DIR / name)
    return parser


def test_start_limits_are_in_unit_section():
    for name in UNITS:
        parser = _parse(name)
        assert parser.has_section("Unit"), name
        assert parser.get("Unit", "StartLimitIntervalSec") == "60", name
        assert parser.get("Unit", "StartLimitBurst") == "5", name


def test_service_resource_caps_and_journal_output():
    for name in UNITS:
        parser = _parse(name)
        assert parser.get("Service", "MemoryMax") == "256M", name
        assert parser.get("Service", "TasksMax") == "64", name
        assert parser.get("Service", "CPUQuota") == "20%", name
        assert parser.get("Service", "StandardOutput") == "journal", name
        assert parser.get("Service", "StandardError") == "journal", name
