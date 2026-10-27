"""Per-panel systemd service profiles and environment override resolution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class ServiceProfile:
    required: Tuple[str, ...] = ()
    optional: Tuple[str, ...] = ()


PROFILES: Dict[str, ServiceProfile] = {
    "standalone": ServiceProfile(
        ("ssh",),
        ("nginx", "apache2", "httpd", "mysql", "redis", "docker"),
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
        (
            "nginx",
            "apache2",
            "httpd",
            "postfix",
            "dovecot",
            "mysql",
            "redis",
            "php-fpm",
        ),
    ),
    "directadmin": ServiceProfile(
        ("directadmin",),
        ("httpd", "nginx", "apache2", "exim", "dovecot", "mysql", "php-fpm", "redis"),
    ),
    "hestiacp": ServiceProfile(
        ("hestia",),
        (
            "nginx",
            "apache2",
            "exim",
            "dovecot",
            "mysql",
            "named",
            "vsftpd",
            "php-fpm",
            "redis",
        ),
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

_PANEL_TO_PROFILE: Tuple[Tuple[str, str], ...] = (
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


def _strip_service_suffix(name: str) -> str:
    value = str(name).strip()
    if value.lower().endswith(".service"):
        return value[: -len(".service")]
    return value


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
    base = _strip_service_suffix(name)
    lowered = base.lower()
    for group in ALIAS_GROUPS:
        if lowered in group:
            return list(group)
    return [base]


def _clean(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    cleaned: List[str] = []
    for raw in values:
        name = _strip_service_suffix(raw)
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
    required = _clean(required_override) or _clean(chosen.required)
    optional = _clean(optional_override) or _clean(chosen.optional)
    required_names = set(required)
    optional = [name for name in optional if name not in required_names]
    return required, optional
