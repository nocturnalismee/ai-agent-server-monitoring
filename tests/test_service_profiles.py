from server_agent.detectors.service_profiles import (
    ALIAS_GROUPS,
    PROFILE_NAMES,
    alias_candidates,
    panel_to_profile,
    profile_name,
    resolve_targets,
)


def test_profile_names_exact():
    expected = frozenset(
        {
            "auto",
            "none",
            "standalone",
            "cpanel",
            "cyberpanel",
            "aapanel",
            "plesk",
            "directadmin",
            "hestiacp",
            "vestacp",
            "cloudpanel",
            "runcloud",
        }
    )
    assert PROFILE_NAMES == expected
    assert isinstance(PROFILE_NAMES, frozenset)


def test_alias_groups_exact_order():
    assert ALIAS_GROUPS == (
        ("ssh", "sshd"),
        ("apache2", "httpd", "apache"),
        ("mysql", "mariadb", "mysqld"),
        ("exim", "exim4"),
        ("named", "bind9", "named-chroot"),
        ("redis", "redis-server"),
        ("powerdns", "pdns"),
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
    assert optional == [
        "named",
        "lsws",
        "cphulkd",
        "pure-ftpd",
        "clamd",
        "spamd",
        "redis",
        "php-fpm",
    ]


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


def test_alias_candidates_start_with_configured_name():
    assert alias_candidates("sshd") == ["sshd", "ssh"]
    assert alias_candidates("httpd") == ["httpd", "apache2", "apache"]
    assert alias_candidates("redis.service") == ["redis", "redis-server"]
    assert alias_candidates("redis-server") == ["redis-server", "redis"]
    assert alias_candidates("powerdns") == ["powerdns", "pdns"]
    assert alias_candidates("pdns") == ["pdns", "powerdns"]
    assert alias_candidates("custom") == ["custom"]


def test_vestacp_defaults_require_vesta():
    required, optional = resolve_targets("vestacp", None)
    assert required == ["vesta"]
    assert optional == [
        "nginx",
        "apache2",
        "exim",
        "dovecot",
        "mysql",
        "named",
        "vsftpd",
        "php-fpm",
        "redis",
    ]


def test_auto_detected_vestacp_requires_vesta():
    required, optional = resolve_targets("auto", "VestaCP")
    assert required == ["vesta"]
    assert "hestia" not in required
    assert "nginx" in optional


def test_panel_to_profile_unknown_is_standalone():
    assert panel_to_profile("Some Unknown Panel") == "standalone"
