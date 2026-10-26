from server_agent.core.models import ServerMetadata
from server_agent.detectors.environment import EnvironmentDetector
from server_agent.detectors.services import ServiceDetector


def test_environment_detector_returns_metadata():
    detector = EnvironmentDetector()
    meta = detector.detect()
    assert isinstance(meta, ServerMetadata)
    assert meta.hostname != ""
    assert meta.short_name != ""
    assert meta.os_name != ""
    assert isinstance(meta.badge(), str)


def test_service_detector_filters_empty():
    detector = ServiceDetector()
    assert detector.filter_installed_services([]) == []
    assert detector.filter_installed_services(["", "   "]) == []


def test_metadata_badge_formatting():
    meta = ServerMetadata(
        os_name="CloudLinux",
        os_version="8.5",
        panel="cPanel",
        web_server="LiteSpeed",
    )
    badge = meta.badge()
    assert "CloudLinux 8.5" in badge
    assert "cPanel" in badge
    assert "LiteSpeed" in badge
