from __future__ import annotations

import os
import platform
import shutil
import socket
from typing import Any, Dict, Optional

from ..core.models import ServerMetadata


def _safe_exists(path_str: str) -> bool:
    try:
        return os.path.exists(path_str)
    except (PermissionError, OSError):
        return False


def _safe_is_dir(path_str: str) -> bool:
    try:
        return os.path.isdir(path_str)
    except (PermissionError, OSError):
        return False


def _safe_read_text(path_str: str) -> str:
    try:
        with open(path_str, "r", encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except (PermissionError, FileNotFoundError, OSError):
        return ""


# Distro IDs from ID and ID_LIKE, used to classify derivatives such as Linux Mint.
_RHEL_IDS = {"cloudlinux", "almalinux", "rocky", "centos", "rhel", "fedora", "ol", "oracle"}
_DEBIAN_IDS = {
    "ubuntu",
    "debian",
    "raspbian",
    "pop",
    "linuxmint",
    "elementary",
    "zorin",
    "kali",
    "neon",
    "mx",
}
_ARCH_IDS = {"arch", "manjaro", "endeavouros", "garuda"}
_ALPINE_IDS = {"alpine"}


class EnvironmentDetector:
    """Auto-detect operating system, hosting control panel, and active software stack."""

    def __init__(self, logger=None):
        self.logger = logger
        self._cached: Optional[ServerMetadata] = None

    def detect(self, force_refresh: bool = False) -> ServerMetadata:
        if self._cached is not None and not force_refresh:
            return self._cached

        meta = ServerMetadata()

        # Hostname
        try:
            meta.hostname = socket.gethostname()
            meta.short_name = meta.hostname.split(".")[0]
        except Exception:
            meta.hostname = "localhost"
            meta.short_name = "localhost"

        # Kernel
        try:
            meta.kernel = platform.release()
        except Exception:
            meta.kernel = ""

        # OS Details
        os_info = self._detect_os()
        meta.os_name = os_info.get("name", platform.system())
        meta.os_version = os_info.get("version", "")
        meta.os_family = os_info.get("family", "linux")

        # Package manager
        meta.package_manager = self._detect_pkg_manager(meta.os_family)

        # Control panel
        panel_name, panel_ver = self._detect_panel()
        meta.panel = panel_name
        meta.panel_version = panel_ver

        # Web server & Database stack
        meta.web_server = self._detect_web_server(meta.panel)
        meta.database = self._detect_database()
        meta.firewall = self._detect_firewall()

        # Specific OS features (e.g., CloudLinux CageFS & LVE)
        meta.features = self._detect_features(meta.os_name)

        self._cached = meta
        if self.logger:
            self.logger.info(
                "Detected environment: OS=%s %s Panel=%s Web=%s DB=%s",
                meta.os_name,
                meta.os_version,
                meta.panel,
                meta.web_server or "none",
                meta.database or "none",
            )
        return meta

    @staticmethod
    def _detect_os() -> Dict[str, str]:
        info = {"name": platform.system(), "version": "", "family": "linux"}
        release_files = ["/etc/os-release", "/usr/lib/os-release"]

        for path in release_files:
            content = _safe_read_text(path)
            if not content:
                continue
            try:
                data: Dict[str, str] = {}
                for line in content.splitlines():
                    if "=" in line and not line.strip().startswith("#"):
                        k, v = line.split("=", 1)
                        data[k.strip()] = v.strip().strip('"\'')

                raw_id = data.get("ID", "").lower()
                id_like = data.get("ID_LIKE", "").lower().split()
                pretty_name = data.get("PRETTY_NAME") or data.get("NAME") or raw_id.title()
                version_id = data.get("VERSION_ID", "")

                info["name"] = pretty_name
                info["version"] = version_id

                tokens = [raw_id, *id_like] if raw_id else list(id_like)
                if any(token in _RHEL_IDS for token in tokens):
                    info["family"] = "rhel"
                elif any(token in _DEBIAN_IDS for token in tokens):
                    info["family"] = "debian"
                elif any(token in _ARCH_IDS for token in tokens):
                    info["family"] = "arch"
                elif any(token in _ALPINE_IDS for token in tokens):
                    info["family"] = "alpine"
                break
            except Exception:
                continue
        return info

    @staticmethod
    def _detect_pkg_manager(os_family: str) -> str:
        for cmd in ("apt-get", "apt", "dnf", "yum", "pacman", "apk"):
            if shutil.which(cmd):
                return cmd
        return {
            "debian": "apt",
            "rhel": "dnf",
            "arch": "pacman",
            "alpine": "apk",
        }.get(os_family, "")

    @staticmethod
    def _detect_panel() -> tuple[str, str]:
        # 1. cPanel / WHM
        if _safe_is_dir("/usr/local/cpanel"):
            ver = _safe_read_text("/usr/local/cpanel/version")
            return "cPanel", ver

        # 2. CyberPanel
        if _safe_is_dir("/usr/local/CyberCP") or _safe_is_dir("/etc/cyberpanel"):
            ver = _safe_read_text("/usr/local/CyberCP/version.txt")
            return "CyberPanel", ver

        # 3. aaPanel / BT-Panel
        if _safe_is_dir("/www/server/panel"):
            return "aaPanel", ""

        # 4. Plesk
        if _safe_is_dir("/usr/local/psa"):
            raw_ver = _safe_read_text("/usr/local/psa/version")
            ver = raw_ver.split()[0] if raw_ver else ""
            return "Plesk", ver

        # 5. CloudPanel
        if _safe_is_dir("/usr/local/clp") or _safe_is_dir("/home/cloudpanel"):
            return "CloudPanel", ""

        # 6. HestiaCP / VestaCP
        if _safe_is_dir("/usr/local/hestia"):
            return "HestiaCP", ""
        if _safe_is_dir("/usr/local/vesta"):
            return "VestaCP", ""

        # 7. DirectAdmin
        if _safe_is_dir("/usr/local/directadmin"):
            return "DirectAdmin", ""

        # 8. RunCloud
        if _safe_is_dir("/etc/runcloud"):
            return "RunCloud", ""

        return "Standalone", ""

    @staticmethod
    def _detect_web_server(panel: str) -> str:
        servers = []
        # OpenLiteSpeed / LiteSpeed
        if _safe_is_dir("/usr/local/lsws") or _safe_exists("/usr/local/lsws/bin/lshttpd"):
            servers.append("OpenLiteSpeed" if panel == "CyberPanel" else "LiteSpeed")

        # Nginx
        if shutil.which("nginx") or _safe_is_dir("/etc/nginx") or _safe_is_dir("/www/server/nginx"):
            servers.append("Nginx")

        # Apache
        if (
            shutil.which("apache2")
            or shutil.which("httpd")
            or _safe_is_dir("/etc/apache2")
            or _safe_is_dir("/etc/httpd")
            or _safe_is_dir("/www/server/apache")
        ):
            servers.append("Apache")

        # Caddy
        if shutil.which("caddy") or _safe_is_dir("/etc/caddy"):
            servers.append("Caddy")

        return " + ".join(servers) if servers else ""

    @staticmethod
    def _detect_database() -> str:
        dbs = []
        # MySQL / MariaDB
        if (
            shutil.which("mariadb")
            or shutil.which("mysql")
            or _safe_is_dir("/var/lib/mysql")
            or _safe_is_dir("/www/server/data")
        ):
            dbs.append("MySQL/MariaDB")

        # PostgreSQL
        if shutil.which("psql") or _safe_is_dir("/var/lib/postgresql"):
            dbs.append("PostgreSQL")

        # Redis
        if shutil.which("redis-server") or _safe_is_dir("/etc/redis"):
            dbs.append("Redis")

        return " + ".join(dbs) if dbs else ""

    @staticmethod
    def _detect_firewall() -> str:
        # CSF (ConfigServer Security & Firewall)
        if _safe_exists("/etc/csf/csf.conf"):
            return "CSF"
        # UFW
        if shutil.which("ufw") and _safe_is_dir("/etc/ufw"):
            return "UFW"
        # Firewalld
        if shutil.which("firewall-cmd") and _safe_is_dir("/etc/firewalld"):
            return "firewalld"
        return "iptables"

    @staticmethod
    def _detect_features(os_name: str) -> Dict[str, Any]:
        features: Dict[str, Any] = {}
        # CloudLinux features
        if "cloudlinux" in os_name.lower():
            features["cagefs"] = _safe_exists("/usr/sbin/cagefsctl")
            features["lve"] = _safe_exists("/proc/lve")
            features["mysql_governor"] = _safe_exists("/usr/bin/dbctl")
        return features
