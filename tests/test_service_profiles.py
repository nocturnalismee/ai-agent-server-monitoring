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
