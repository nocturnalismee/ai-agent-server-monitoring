"""Tests for AI system instruction construction."""

import pytest

from server_agent.ai.prompts import build_system_instruction
from server_agent.core.models import ServerMetadata


def _metadata(**overrides):
    values = {
        "hostname": "web1.example.com",
        "short_name": "web1",
        "os_name": "Ubuntu",
        "os_version": "22.04",
        "os_family": "debian",
        "kernel": "5.15.0",
        "panel": "Standalone",
        "panel_version": "",
        "web_server": "Nginx",
        "database": "MySQL 8",
        "firewall": "ufw",
        "package_manager": "apt",
        "features": {},
    }
    values.update(overrides)
    return ServerMetadata(**values)


def test_without_metadata_uses_generic_prompt():
    text = build_system_instruction()

    assert "Senior Linux Site Reliability Engineer" in text
    assert "under 200 words" in text
    assert "Likely Cause" in text
    assert "Target Server Environment" not in text


def test_metadata_includes_environment_bullets():
    text = build_system_instruction(
        _metadata(features={"cagefs": True, "lve": False})
    )

    assert "• OS: Ubuntu 22.04 (family: debian, pkg: apt)" in text
    assert "• Control Panel: Standalone" in text
    assert "• Web Stack: Nginx" in text
    assert "• Database: MySQL 8" in text
    assert "• Firewall: ufw" in text
    assert "• Special Features: cagefs" in text


def test_empty_metadata_values_use_fallbacks():
    text = build_system_instruction(
        _metadata(web_server="", database="", package_manager="", firewall="")
    )

    assert "pkg: standard" in text
    assert "Web Stack: None detected" in text
    assert "Database: None detected" in text
    assert "Firewall: iptables" in text


@pytest.mark.parametrize(
    "overrides,expected",
    [
        ({"os_name": "CloudLinux 8"}, "cagefsctl"),
        ({"panel": "cPanel/WHM"}, "whmapi1"),
        ({"panel": "CyberPanel"}, "lswsctrl"),
        ({"panel": "aaPanel"}, "bt status"),
        ({"panel": "CloudPanel"}, "clpctl"),
        ({"panel": "Plesk"}, "plesk bin"),
        ({"panel": "DirectAdmin"}, "CustomBuild"),
        ({"panel": "HestiaCP"}, "v-list-sys-services"),
        ({"panel": "VestaCP"}, "v-list-sys-services"),
        ({"panel": "RunCloud"}, "runcloud-agent"),
    ],
)
def test_environment_specific_hints(overrides, expected):
    assert expected in build_system_instruction(_metadata(**overrides))


def test_web_and_database_specific_hints():
    nginx_prompt = build_system_instruction(_metadata(web_server="Nginx", database="MySQL 8"))
    assert "nginx -t" in nginx_prompt
    assert "mysqladmin ping" in nginx_prompt

    apache_prompt = build_system_instruction(
        _metadata(web_server="Apache", database="PostgreSQL")
    )
    assert "apachectl configtest" in apache_prompt
    assert "pg_isready" in apache_prompt

    lsws_prompt = build_system_instruction(
        _metadata(panel="Standalone", web_server="LiteSpeed")
    )
    assert "lswsctrl status" in lsws_prompt


def test_firewall_specific_hints():
    csf_prompt = build_system_instruction(_metadata(firewall="csf"))
    assert "csf -d <IP>" in csf_prompt

    ufw_prompt = build_system_instruction(_metadata(firewall="ufw"))
    assert "ufw deny from <IP>" in ufw_prompt

    firewalld_prompt = build_system_instruction(_metadata(firewall="firewalld"))
    assert "firewall-cmd" in firewalld_prompt


def test_instructions_interpolate_os_and_panel():
    text = build_system_instruction(_metadata(panel="cPanel/WHM", os_family="rhel"))

    assert "this OS (rhel)" in text
    assert "Control Panel (cPanel/WHM)" in text


def test_security_rule_is_present():
    text = build_system_instruction(_metadata())

    assert "SECURITY RULE" in text
    assert "prompt-injections" in text
    assert "rm -rf" in text


def test_generic_prompt_includes_security_rule():
    generic = build_system_instruction()

    assert "SECURITY RULE" in generic
    assert "prompt-injections" in generic
    assert "rm -rf" in generic
