import json
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
    assert AIAnalyzer._extract_gemini_text(response) == "Likely cause: high load"
    assert AIAnalyzer._extract_gemini_text({}) == ""


def test_extract_text_from_openai_and_deepseek_response():
    response = {
        "choices": [{
            "message": {"content": "Likely cause: OOM on mysqld"}
        }]
    }
    assert AIAnalyzer._extract_openai_text(response) == "Likely cause: OOM on mysqld"
    assert AIAnalyzer._extract_openai_text({}) == ""


def test_extract_text_from_claude_response():
    response = {
        "content": [
            {"type": "text", "text": "Likely cause: Disk full on /"}
        ]
    }
    assert AIAnalyzer._extract_claude_text(response) == "Likely cause: Disk full on /"
    assert AIAnalyzer._extract_claude_text({}) == ""


def test_build_request_for_deepseek():
    cfg = SimpleNamespace(
        ai_enabled=True,
        ai_provider="deepseek",
        ai_api_key="sk-deepseek-test",
        resolved_ai_model=lambda: "deepseek-chat",
        resolved_ai_base_url=lambda: "https://api.deepseek.com/v1",
        ai_timeout_seconds=10,
        ai_max_output_tokens=300,
        ai_rate_limit_per_minute=10,
        server_name="test-server",
        environment="test",
    )
    analyzer = AIAnalyzer(cfg, logging.getLogger("test"))
    req = analyzer._build_request({"metric": "cpu"})

    assert req.full_url == "https://api.deepseek.com/v1/chat/completions"
    assert req.headers["Authorization"] == "Bearer sk-deepseek-test"
    assert req.headers["Content-type"] == "application/json; charset=utf-8"
    body = json.loads(req.data.decode("utf-8"))
    assert body["model"] == "deepseek-chat"
    assert body["max_tokens"] == 300
    assert len(body["messages"]) == 2
    assert body["messages"][0]["role"] == "system"


def test_build_request_for_claude():
    cfg = SimpleNamespace(
        ai_enabled=True,
        ai_provider="claude",
        ai_api_key="sk-ant-test",
        resolved_ai_model=lambda: "claude-3-5-haiku-20241022",
        resolved_ai_base_url=lambda: "https://api.anthropic.com/v1",
        ai_timeout_seconds=10,
        ai_max_output_tokens=300,
        ai_rate_limit_per_minute=10,
        server_name="test-server",
        environment="test",
    )
    analyzer = AIAnalyzer(cfg, logging.getLogger("test"))
    req = analyzer._build_request({"metric": "cpu"})

    assert req.full_url == "https://api.anthropic.com/v1/messages"
    assert req.headers["X-api-key"] == "sk-ant-test"
    assert req.headers["Anthropic-version"] == "2023-06-01"
    body = json.loads(req.data.decode("utf-8"))
    assert body["model"] == "claude-3-5-haiku-20241022"
    assert "system" in body


def test_build_request_for_gemini():
    cfg = SimpleNamespace(
        ai_enabled=True,
        ai_provider="gemini",
        ai_api_key="gemini-key-test",
        resolved_ai_model=lambda: "gemini-1.5-flash",
        resolved_ai_base_url=lambda: "https://generativelanguage.googleapis.com/v1beta/models",
        ai_timeout_seconds=10,
        ai_max_output_tokens=300,
        ai_rate_limit_per_minute=10,
        server_name="test-server",
        environment="test",
    )
    analyzer = AIAnalyzer(cfg, logging.getLogger("test"))
    req = analyzer._build_request({"metric": "cpu"})

    assert "gemini-1.5-flash:generateContent" in req.full_url
    assert "key=gemini-key-test" in req.full_url
    assert req.headers["X-goog-api-key"] == "gemini-key-test"


def test_ai_rate_limiting_blocks_after_threshold():
    config = SimpleNamespace(
        ai_enabled=True,
        ai_provider="deepseek",
        ai_api_key="test-key",
        resolved_ai_model=lambda: "deepseek-chat",
        resolved_ai_base_url=lambda: "https://api.deepseek.com/v1",
        ai_rate_limit_per_minute=2,
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


def test_ai_rate_limiting_sliding_window():
    config = SimpleNamespace(
        ai_enabled=True,
        ai_provider="deepseek",
        ai_api_key="test-key",
        resolved_ai_model=lambda: "deepseek-chat",
        resolved_ai_base_url=lambda: "https://api.deepseek.com/v1",
        ai_rate_limit_per_minute=1,
    )
    logger = logging.getLogger("test")
    analyzer = AIAnalyzer(config, logger)

    assert analyzer._is_rate_limited() is False
    assert analyzer._is_rate_limited() is True

    # Simulate 65 seconds passed
    analyzer._request_history = [t - 65.0 for t in analyzer._request_history]
    assert analyzer._is_rate_limited() is False
