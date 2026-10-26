import pytest

from server_agent.core.models import ServerMetadata
from server_agent.detectors import environment as env
from server_agent.detectors.environment import EnvironmentDetector


class _Logger:
    def __init__(self):
        self.calls = []

    def info(self, *args):
        self.calls.append(args)


def _patch_read_text(monkeypatch, mapping):
    monkeypatch.setattr(env, "_safe_read_text", lambda path: mapping.get(path, ""))


def _patch_safe_probes(monkeypatch, dirs=(), exists=()):
    dirs = set(dirs)
    exists = set(exists)
    monkeypatch.setattr(env, "_safe_is_dir", lambda path: path in dirs)
    monkeypatch.setattr(env, "_safe_exists", lambda path: path in exists)


def _patch_which(monkeypatch, commands=()):
    commands = set(commands)
    monkeypatch.setattr(env.shutil, "which", lambda cmd: cmd if cmd in commands else None)


def _patch_detect_base(monkeypatch, os_release="", which=()):
    _patch_safe_probes(monkeypatch)
    _patch_which(monkeypatch, which)
    monkeypatch.setattr(env.socket, "gethostname", lambda: "web01.example.com")
    monkeypatch.setattr(env.platform, "release", lambda: "6.1.0-test")
    monkeypatch.setattr(env.platform, "system", lambda: "Linux")
    _patch_read_text(
        monkeypatch,
        {"/etc/os-release": os_release},
    )


def test_safe_exists_returns_true_and_false(monkeypatch):
    monkeypatch.setattr(env.os.path, "exists", lambda path: path == "/present")

    assert env._safe_exists("/present") is True
    assert env._safe_exists("/missing") is False


@pytest.mark.parametrize("exc", [PermissionError, OSError])
def test_safe_exists_returns_false_on_os_errors(monkeypatch, exc):
    def boom(path):
        raise exc

    monkeypatch.setattr(env.os.path, "exists", boom)

    assert env._safe_exists("/anything") is False


def test_safe_is_dir_returns_true_and_false(monkeypatch):
    monkeypatch.setattr(env.os.path, "isdir", lambda path: path == "/present")

    assert env._safe_is_dir("/present") is True
    assert env._safe_is_dir("/missing") is False


@pytest.mark.parametrize("exc", [PermissionError, OSError])
def test_safe_is_dir_returns_false_on_os_errors(monkeypatch, exc):
    def boom(path):
        raise exc

    monkeypatch.setattr(env.os.path, "isdir", boom)

    assert env._safe_is_dir("/anything") is False


def test_safe_read_text_reads_and_strips(tmp_path):
    release = tmp_path / "os-release"
    release.write_text("\n ID=debian \n", encoding="utf-8")

    assert env._safe_read_text(str(release)) == "ID=debian"


def test_safe_read_text_replaces_invalid_utf8(tmp_path):
    release = tmp_path / "os-release"
    release.write_bytes(b"abc\xff")

    assert env._safe_read_text(str(release)) == "abc\ufffd"


def test_safe_read_text_returns_empty_for_missing_file(tmp_path):
    assert env._safe_read_text(str(tmp_path / "missing")) == ""


@pytest.mark.parametrize("exc", [PermissionError, OSError])
def test_safe_read_text_returns_empty_on_os_errors(monkeypatch, exc):
    def boom(*args, **kwargs):
        raise exc

    monkeypatch.setattr("builtins.open", boom)

    assert env._safe_read_text("/anything") == ""


@pytest.mark.parametrize(
    "content,expected_name,expected_version,expected_family",
    [
        (
            'ID=almalinux\nPRETTY_NAME="AlmaLinux 9.3"\nVERSION_ID="9.3"\n',
            "AlmaLinux 9.3",
            "9.3",
            "rhel",
        ),
        ('ID=centos\nNAME="CentOS Linux"\nVERSION_ID=7\n', "CentOS Linux", "7", "rhel"),
        ('ID=UBUNTU\nNAME="Ubuntu"\nVERSION_ID="22.04"\n', "Ubuntu", "22.04", "debian"),
        ("ID=arch\nVERSION_ID=rolling\n", "Arch", "rolling", "arch"),
        ("ID=alpine\nVERSION_ID=3.19\n", "Alpine", "3.19", "alpine"),
        ('ID=gentoo\nPRETTY_NAME="Gentoo Linux"\n', "Gentoo Linux", "", "linux"),
    ],
)
def test_detect_os_maps_id_to_family(
    monkeypatch, content, expected_name, expected_version, expected_family
):
    monkeypatch.setattr(env.platform, "system", lambda: "Linux")
    _patch_read_text(monkeypatch, {"/etc/os-release": content})

    info = EnvironmentDetector._detect_os()

    assert info == {
        "name": expected_name,
        "version": expected_version,
        "family": expected_family,
    }


def test_detect_os_strips_quoted_values(monkeypatch):
    content = 'ID="ubuntu"\nPRETTY_NAME="Ubuntu 24.04 LTS"\nVERSION_ID="24.04"\n'
    monkeypatch.setattr(env.platform, "system", lambda: "Linux")
    _patch_read_text(monkeypatch, {"/etc/os-release": content})

    info = EnvironmentDetector._detect_os()

    assert info["name"] == "Ubuntu 24.04 LTS"
    assert info["version"] == "24.04"
    assert info["family"] == "debian"


def test_detect_os_ignores_malformed_lines_and_comments(monkeypatch):
    content = '# comment\nBADLINE\n\nID=debian\n=orphan\nNAME="Debian GNU/Linux"\nVERSION_ID=12\n'
    monkeypatch.setattr(env.platform, "system", lambda: "Linux")
    _patch_read_text(monkeypatch, {"/etc/os-release": content})

    info = EnvironmentDetector._detect_os()

    assert info == {"name": "Debian GNU/Linux", "version": "12", "family": "debian"}


def test_detect_os_uses_id_title_when_no_names_present(monkeypatch):
    monkeypatch.setattr(env.platform, "system", lambda: "Linux")
    _patch_read_text(monkeypatch, {"/etc/os-release": "ID=rocky\nVERSION_ID=9.4\n"})

    info = EnvironmentDetector._detect_os()

    assert info == {"name": "Rocky", "version": "9.4", "family": "rhel"}


def test_detect_os_unknown_id_without_names(monkeypatch):
    monkeypatch.setattr(env.platform, "system", lambda: "Linux")
    _patch_read_text(monkeypatch, {"/etc/os-release": "ID=customos\n"})

    info = EnvironmentDetector._detect_os()

    assert info["name"] == "Customos"
    assert info["family"] == "linux"


def test_detect_os_uses_id_like_when_id_unknown(monkeypatch):
    content = 'ID=customos\nID_LIKE="ubuntu debian"\nPRETTY_NAME="Custom OS"\n'
    monkeypatch.setattr(env.platform, "system", lambda: "Linux")
    _patch_read_text(monkeypatch, {"/etc/os-release": content})

    info = EnvironmentDetector._detect_os()

    assert info["family"] == "debian"


def test_detect_os_maps_linux_mint_to_debian(monkeypatch):
    content = 'ID=linuxmint\nID_LIKE="ubuntu debian"\nPRETTY_NAME="Linux Mint"\n'
    monkeypatch.setattr(env.platform, "system", lambda: "Linux")
    _patch_read_text(monkeypatch, {"/etc/os-release": content})

    info = EnvironmentDetector._detect_os()

    assert info["family"] == "debian"


def test_detect_os_uses_id_like_for_rhel_derivatives(monkeypatch):
    content = 'ID=customel\nID_LIKE="rhel centos fedora"\nPRETTY_NAME="Custom EL"\n'
    monkeypatch.setattr(env.platform, "system", lambda: "Linux")
    _patch_read_text(monkeypatch, {"/etc/os-release": content})

    info = EnvironmentDetector._detect_os()

    assert info["family"] == "rhel"


def test_detect_os_ignores_unsupported_id_like(monkeypatch):
    content = 'ID=customos\nID_LIKE="gentoo"\nPRETTY_NAME="Custom OS"\n'
    monkeypatch.setattr(env.platform, "system", lambda: "Linux")
    _patch_read_text(monkeypatch, {"/etc/os-release": content})

    info = EnvironmentDetector._detect_os()

    assert info["family"] == "linux"


def test_detect_os_falls_back_to_usr_lib_release(monkeypatch):
    monkeypatch.setattr(env.platform, "system", lambda: "Linux")
    _patch_read_text(
        monkeypatch,
        {"/usr/lib/os-release": 'ID=alpine\nPRETTY_NAME="Alpine Linux"\nVERSION_ID=3.20\n'},
    )

    info = EnvironmentDetector._detect_os()

    assert info == {"name": "Alpine Linux", "version": "3.20", "family": "alpine"}


def test_detect_os_first_release_file_wins(monkeypatch):
    monkeypatch.setattr(env.platform, "system", lambda: "Linux")
    _patch_read_text(
        monkeypatch,
        {
            "/etc/os-release": "ID=debian\nPRETTY_NAME=Debian\n",
            "/usr/lib/os-release": "ID=alpine\nPRETTY_NAME=Alpine\n",
        },
    )

    info = EnvironmentDetector._detect_os()

    assert info == {"name": "Debian", "version": "", "family": "debian"}


def test_detect_os_defaults_when_no_release_file(monkeypatch):
    monkeypatch.setattr(env.platform, "system", lambda: "Linux")
    _patch_read_text(monkeypatch, {})

    info = EnvironmentDetector._detect_os()

    assert info == {"name": "Linux", "version": "", "family": "linux"}


_PANEL_CASES = [
    (["/usr/local/cpanel"], {"/usr/local/cpanel/version": "110.0.2"}, "cPanel", "110.0.2"),
    (["/usr/local/CyberCP"], {"/usr/local/CyberCP/version.txt": "2.3.4"}, "CyberPanel", "2.3.4"),
    (["/etc/cyberpanel"], {}, "CyberPanel", ""),
    (["/www/server/panel"], {}, "aaPanel", ""),
    (
        ["/usr/local/psa"],
        {"/usr/local/psa/version": "18.0.60 Ubuntu 22.04 1234567890"},
        "Plesk",
        "18.0.60",
    ),
    (["/usr/local/psa"], {}, "Plesk", ""),
    (["/usr/local/clp"], {}, "CloudPanel", ""),
    (["/home/cloudpanel"], {}, "CloudPanel", ""),
    (["/usr/local/hestia"], {}, "HestiaCP", ""),
    (["/usr/local/vesta"], {}, "VestaCP", ""),
    (["/usr/local/directadmin"], {}, "DirectAdmin", ""),
    (["/etc/runcloud"], {}, "RunCloud", ""),
    ([], {}, "Standalone", ""),
]


@pytest.mark.parametrize("dirs,files,expected_name,expected_version", _PANEL_CASES)
def test_detect_panel_checks_each_known_location(
    monkeypatch, dirs, files, expected_name, expected_version
):
    _patch_safe_probes(monkeypatch, dirs=dirs)
    _patch_read_text(monkeypatch, files)

    assert EnvironmentDetector._detect_panel() == (expected_name, expected_version)


def test_detect_panel_prefers_cpanel_when_several_exist(monkeypatch):
    _patch_safe_probes(
        monkeypatch,
        dirs=[
            "/usr/local/cpanel",
            "/usr/local/CyberCP",
            "/www/server/panel",
            "/usr/local/psa",
            "/etc/runcloud",
        ],
    )
    _patch_read_text(monkeypatch, {"/usr/local/cpanel/version": "110.0"})

    assert EnvironmentDetector._detect_panel() == ("cPanel", "110.0")


@pytest.mark.parametrize(
    "which,dirs,exists,expected",
    [
        ((), (), (), ""),
        ((), (), ("/usr/local/lsws/bin/lshttpd",), "LiteSpeed"),
        ((), ("/usr/local/lsws",), (), "LiteSpeed"),
        (("nginx",), (), (), "Nginx"),
        ((), ("/etc/nginx",), (), "Nginx"),
        ((), ("/www/server/nginx",), (), "Nginx"),
        (("apache2",), (), (), "Apache"),
        (("httpd",), (), (), "Apache"),
        ((), ("/etc/apache2",), (), "Apache"),
        ((), ("/etc/httpd",), (), "Apache"),
        ((), ("/www/server/apache",), (), "Apache"),
        (("caddy",), (), (), "Caddy"),
        ((), ("/etc/caddy",), (), "Caddy"),
        (("nginx", "apache2", "caddy"), (), (), "Nginx + Apache + Caddy"),
    ],
)
def test_detect_web_server_branches(monkeypatch, which, dirs, exists, expected):
    _patch_which(monkeypatch, which)
    _patch_safe_probes(monkeypatch, dirs=dirs, exists=exists)

    assert EnvironmentDetector._detect_web_server("Standalone") == expected


@pytest.mark.parametrize(
    "which,dirs,exists,expected",
    [
        ((), ("/usr/local/lsws",), (), "OpenLiteSpeed"),
        ((), (), ("/usr/local/lsws/bin/lshttpd",), "OpenLiteSpeed"),
    ],
)
def test_detect_web_server_uses_openlitespeed_for_cyberpanel(
    monkeypatch, which, dirs, exists, expected
):
    _patch_which(monkeypatch, which)
    _patch_safe_probes(monkeypatch, dirs=dirs, exists=exists)

    assert EnvironmentDetector._detect_web_server("CyberPanel") == expected


@pytest.mark.parametrize(
    "which,dirs,expected",
    [
        ((), (), ""),
        (("mariadb",), (), "MySQL/MariaDB"),
        (("mysql",), (), "MySQL/MariaDB"),
        ((), ("/var/lib/mysql",), "MySQL/MariaDB"),
        ((), ("/www/server/data",), "MySQL/MariaDB"),
        (("psql",), (), "PostgreSQL"),
        ((), ("/var/lib/postgresql",), "PostgreSQL"),
        (("redis-server",), (), "Redis"),
        ((), ("/etc/redis",), "Redis"),
        (
            ("mariadb", "psql", "redis-server"),
            (),
            "MySQL/MariaDB + PostgreSQL + Redis",
        ),
    ],
)
def test_detect_database_branches(monkeypatch, which, dirs, expected):
    _patch_which(monkeypatch, which)
    _patch_safe_probes(monkeypatch, dirs=dirs)

    assert EnvironmentDetector._detect_database() == expected


@pytest.mark.parametrize(
    "which,dirs,exists,expected",
    [
        ((), (), (), "iptables"),
        ((), (), ("/etc/csf/csf.conf",), "CSF"),
        (("ufw",), ("/etc/ufw",), (), "UFW"),
        (("ufw",), (), (), "iptables"),
        ((), ("/etc/ufw",), (), "iptables"),
        (("firewall-cmd",), ("/etc/firewalld",), (), "firewalld"),
        (("firewall-cmd",), (), (), "iptables"),
        (("ufw", "firewall-cmd"), ("/etc/ufw", "/etc/firewalld"), (), "UFW"),
        (
            ("ufw", "firewall-cmd"),
            ("/etc/ufw", "/etc/firewalld"),
            ("/etc/csf/csf.conf",),
            "CSF",
        ),
    ],
)
def test_detect_firewall_branches(monkeypatch, which, dirs, exists, expected):
    _patch_which(monkeypatch, which)
    _patch_safe_probes(monkeypatch, dirs=dirs, exists=exists)

    assert EnvironmentDetector._detect_firewall() == expected


def test_detect_features_returns_empty_for_non_cloudlinux(monkeypatch):
    def unexpected_probe(path):
        pytest.fail(f"unexpected filesystem probe: {path}")

    monkeypatch.setattr(env, "_safe_exists", unexpected_probe)

    assert EnvironmentDetector._detect_features("Ubuntu 22.04") == {}


@pytest.mark.parametrize("os_name", ["CloudLinux 8.5", "cloudlinux"])
def test_detect_features_reports_cloudlinux_tools(monkeypatch, os_name):
    _patch_safe_probes(
        monkeypatch,
        exists=["/usr/sbin/cagefsctl", "/proc/lve", "/usr/bin/dbctl"],
    )

    assert EnvironmentDetector._detect_features(os_name) == {
        "cagefs": True,
        "lve": True,
        "mysql_governor": True,
    }


def test_detect_features_reports_false_when_cloudlinux_tools_missing(monkeypatch):
    _patch_safe_probes(monkeypatch)

    assert EnvironmentDetector._detect_features("CloudLinux 8.5") == {
        "cagefs": False,
        "lve": False,
        "mysql_governor": False,
    }


@pytest.mark.parametrize(
    "available,expected",
    [
        ({"apt-get", "apt", "dnf", "yum", "pacman", "apk"}, "apt-get"),
        ({"apt", "dnf"}, "apt"),
        ({"dnf", "yum"}, "dnf"),
        ({"yum"}, "yum"),
        ({"pacman"}, "pacman"),
        ({"apk"}, "apk"),
    ],
)
def test_detect_pkg_manager_prefers_first_available(monkeypatch, available, expected):
    _patch_which(monkeypatch, available)

    assert EnvironmentDetector._detect_pkg_manager("linux") == expected


@pytest.mark.parametrize(
    "family,expected",
    [
        ("debian", "apt"),
        ("rhel", "dnf"),
        ("arch", "pacman"),
        ("alpine", "apk"),
        ("linux", ""),
    ],
)
def test_detect_pkg_manager_falls_back_by_family(monkeypatch, family, expected):
    monkeypatch.setattr(env.shutil, "which", lambda cmd: None)

    assert EnvironmentDetector._detect_pkg_manager(family) == expected


def test_detect_populates_all_metadata_fields(monkeypatch):
    _patch_detect_base(
        monkeypatch,
        os_release='ID=almalinux\nPRETTY_NAME="AlmaLinux 9.3"\nVERSION_ID="9.3"\n',
    )

    meta = EnvironmentDetector().detect()

    assert isinstance(meta, ServerMetadata)
    assert meta.hostname == "web01.example.com"
    assert meta.short_name == "web01"
    assert meta.kernel == "6.1.0-test"
    assert meta.os_name == "AlmaLinux 9.3"
    assert meta.os_version == "9.3"
    assert meta.os_family == "rhel"
    assert meta.package_manager == "dnf"
    assert meta.panel == "Standalone"
    assert meta.panel_version == ""
    assert meta.web_server == ""
    assert meta.database == ""
    assert meta.firewall == "iptables"
    assert meta.features == {}


def test_detect_caches_until_force_refresh(monkeypatch):
    _patch_detect_base(monkeypatch)
    reads = {"count": 0}

    def counting_read(path):
        reads["count"] += 1
        return ""

    monkeypatch.setattr(env, "_safe_read_text", counting_read)

    detector = EnvironmentDetector()
    first = detector.detect()
    reads_after_first = reads["count"]

    assert reads_after_first > 0
    assert detector.detect() is first
    assert reads["count"] == reads_after_first

    refreshed = detector.detect(force_refresh=True)

    assert refreshed is not first
    assert reads["count"] > reads_after_first


def test_detect_uses_localhost_when_hostname_and_kernel_lookups_fail(monkeypatch):
    _patch_detect_base(monkeypatch)

    def boom():
        raise RuntimeError("lookup failed")

    monkeypatch.setattr(env.socket, "gethostname", boom)
    monkeypatch.setattr(env.platform, "release", boom)

    meta = EnvironmentDetector().detect()

    assert meta.hostname == "localhost"
    assert meta.short_name == "localhost"
    assert meta.kernel == ""


def test_detect_logs_summary_when_logger_is_provided(monkeypatch):
    _patch_detect_base(monkeypatch)
    logger = _Logger()

    meta = EnvironmentDetector(logger=logger).detect()

    assert len(logger.calls) == 1
    log_args = logger.calls[0]
    assert log_args[0] == "Detected environment: OS=%s %s Panel=%s Web=%s DB=%s"
    assert log_args[1:] == (meta.os_name, meta.os_version, meta.panel, "none", "none")


def test_metadata_badge_omits_standalone_panel_and_empty_version():
    meta = ServerMetadata(os_name="Debian", panel="Standalone", web_server="Nginx")

    assert meta.badge() == "Debian · Nginx"


def test_metadata_badge_defaults_to_linux_server_when_empty():
    assert ServerMetadata().badge() == "Linux Server"


def test_metadata_badge_includes_panel_without_version():
    meta = ServerMetadata(os_name="Ubuntu", panel="cPanel")

    assert meta.badge() == "Ubuntu · cPanel"
