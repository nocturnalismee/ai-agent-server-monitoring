from __future__ import annotations

import os
import platform
import shutil
import socket
from pathlib import Path
from typing import Any, Dict, Optional

from ..core.models import ServerMetadata


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
        release_files = [Path("/etc/os-release"), Path("/usr/lib/os-release")]

        for path in release_files:
            if not path.exists():
                continue
            try:
                data: Dict[str, str] = {}
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    if "=" in line and not line.strip().startswith("#"):
                        k, v = line.split("=", 1)
                        data[k.strip()] = v.strip().strip('"\'')

                raw_id = data.get("ID", "").lower()
                pretty_name = data.get("PRETTY_NAME") or data.get("NAME") or raw_id.title()
                version_id = data.get("VERSION_ID", "")

                info["name"] = pretty_name
                info["version"] = version_id

                if raw_id in {"cloudlinux", "almalinux", "rocky", "centos", "rhel", "fedora", "ol"}:
                    info["family"] = "rhel"
                elif raw_id in {"ubuntu", "debian", "raspbian", "pop"}:
                    info["family"] = "debian"
                elif raw_id in {"arch", "manjaro"}:
                    info["family"] = "arch"
                elif raw_id in {"alpine"}:
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
        return "apt" if os_family == "debian" else ("dnf" if os_family == "rhel" else "")

    @staticmethod
    def _detect_panel() -> tuple[str, str]:
        # 1. cPanel / WHM
        if Path("/usr/local/cpanel").is_dir():
            ver = ""
            ver_file = Path("/usr/local/cpanel/version")
            if ver_file.exists():
                try:
                    ver = ver_file.read_text().strip()
                except Exception:
                    pass
            return "cPanel", ver

        # 2. CyberPanel
        if Path("/usr/local/CyberCP").is_dir() or Path("/etc/cyberpanel").is_dir():
            ver = ""
            ver_file = Path("/usr/local/CyberCP/version.txt")
            if ver_file.exists():
                try:
                    ver = ver_file.read_text().strip()
                except Exception:
                    pass
            return "CyberPanel", ver

        # 3. aaPanel / BT-Panel
        if Path("/www/server/panel").is_dir():
            ver = ""
            ver_file = Path("/www/server/panel/class/common.py")
            if ver_file.exists():
                ver = "v6.x"
            return "aaPanel", ver

        # 4. Plesk
        if Path("/usr/local/psa").is_dir():
            ver = ""
            ver_file = Path("/usr/local/psa/version")
            if ver_file.exists():
                try:
                    ver = ver_file.read_text().strip().split()[0]
                except Exception:
                    pass
            return "Plesk", ver

        # 5. CloudPanel
        if Path("/usr/local/clp").is_dir() or Path("/home/cloudpanel").is_dir():
            return "CloudPanel", ""

        # 6. HestiaCP / VestaCP
        if Path("/usr/local/hestia").is_dir():
            return "HestiaCP", ""
        if Path("/usr/local/vesta").is_dir():
            return "VestaCP", ""

        # 7. DirectAdmin
        if Path("/usr/local/directadmin").is_dir():
            return "DirectAdmin", ""

        # 8. RunCloud
        if Path("/etc/runcloud").is_dir():
            return "RunCloud", ""

        return "Standalone", ""

    @staticmethod
    def _detect_web_server(panel: str) -> str:
        servers = []
        # OpenLiteSpeed / LiteSpeed
        if Path("/usr/local/lsws").is_dir() or Path("/usr/local/lsws/bin/lshttpd").exists():
            servers.append("OpenLiteSpeed" if panel == "CyberPanel" else "LiteSpeed")

        # Nginx
        if shutil.which("nginx") or Path("/etc/nginx").is_dir() or Path("/www/server/nginx").is_dir():
            servers.append("Nginx")

        # Apache
        if (
            shutil.which("apache2")
            or shutil.which("httpd")
            or Path("/etc/apache2").is_dir()
            or Path("/etc/httpd").is_dir()
            or Path("/www/server/apache").is_dir()
        ):
            servers.append("Apache")

        # Caddy
        if shutil.which("caddy") or Path("/etc/caddy").is_dir():
            servers.append("Caddy")

        return " + ".join(servers) if servers else ""

    @staticmethod
    def _detect_database() -> str:
        dbs = []
        # MySQL / MariaDB
        if (
            shutil.which("mariadb")
            or shutil.which("mysql")
            or Path("/var/lib/mysql").is_dir()
            or Path("/www/server/data").is_dir()
        ):
            dbs.append("MySQL/MariaDB")

        # PostgreSQL
        if shutil.which("psql") or Path("/var/lib/postgresql").is_dir():
            dbs.append("PostgreSQL")

        # Redis
        if shutil.which("redis-server") or Path("/etc/redis").is_dir():
            dbs.append("Redis")

        return " + ".join(dbs) if dbs else ""

    @staticmethod
    def _detect_firewall() -> str:
        # CSF (ConfigServer Security & Firewall)
        if Path("/etc/csf/csf.conf").exists():
            return "CSF"
        # UFW
        if shutil.which("ufw") and Path("/etc/ufw").is_dir():
            return "UFW"
        # Firewalld
        if shutil.which("firewall-cmd") and Path("/etc/firewalld").is_dir():
            return "firewalld"
        return "iptables"

    @staticmethod
    def _detect_features(os_name: str) -> Dict[str, Any]:
        features: Dict[str, Any] = {}
        # CloudLinux features
        if "cloudlinux" in os_name.lower():
            features["cagefs"] = Path("/usr/sbin/cagefsctl").exists()
            features["lve"] = Path("/proc/lve").exists()
            features["mysql_governor"] = Path("/usr/bin/dbctl").exists()
        return features
