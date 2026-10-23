import logging
from types import SimpleNamespace

from server_agent.ai import AIAnalyzer
from server_agent.models import Incident


def test_extract_text_from_gemini_response():
    response = {
        "candidates": [{
            "content": {"parts": [{"text": "Likely cause"}, {"text": ": high load"}]}
        }]
    }
    assert AIAnalyzer._extract_text(response) == "Likely cause: high load"


def test_extract_text_handles_missing_candidates():
    assert AIAnalyzer._extract_text({}) == ""


def test_gemini_rate_limiting_blocks_after_threshold():
    config = SimpleNamespace(
        gemini_enabled=True,
        gemini_api_key="test-key",
        gemini_rate_limit_per_minute=2,
    )
    logger = logging.getLogger("test")
    analyzer = AIAnalyzer(config, logger)

    incident = Incident(
        kind="health",
        severity="WARNING",
        title="CPU high",
        summary="CPU is 90%",
        fingerprint="cpu:test",
    )

    assert analyzer._is_rate_limited() is False
    assert analyzer._is_rate_limited() is False
    assert analyzer._is_rate_limited() is True
    assert analyzer.analyze(incident) == ""


def test_gemini_rate_limiting_sliding_window():
    config = SimpleNamespace(
        gemini_enabled=True,
        gemini_api_key="test-key",
        gemini_rate_limit_per_minute=1,
    )
    logger = logging.getLogger("test")
    analyzer = AIAnalyzer(config, logger)

    assert analyzer._is_rate_limited() is False
    assert analyzer._is_rate_limited() is True

    # Simulate 65 seconds passed
    analyzer._request_history = [t - 65.0 for t in analyzer._request_history]
    assert analyzer._is_rate_limited() is False

