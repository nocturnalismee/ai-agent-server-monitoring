import io
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

import pytest

from server_agent.ai import analyzer as analyzer_module
from server_agent.ai.analyzer import AIAnalyzer
from server_agent.core.models import Incident, ServerMetadata


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _ExplodingBody:
    def read(self, amt=None):
        raise OSError("body unavailable")


def _incident(**overrides):
    values = {
        "kind": "health",
        "severity": "WARNING",
        "title": "CPU high",
        "summary": "CPU is 90%",
        "fingerprint": "cpu:test",
    }
    values.update(overrides)
    return Incident(**values)


def _config(
    provider="deepseek",
    model="deepseek-chat",
    base_url="https://api.deepseek.com/v1",
    **overrides,
):
    cfg = SimpleNamespace(
        ai_enabled=True,
        ai_provider=provider,
        ai_api_key="sk-test-key",
        ai_timeout_seconds=7,
        ai_max_output_tokens=256,
        ai_rate_limit_per_minute=10,
        server_name="srv-1",
        environment="production",
        resolved_ai_model=lambda: model,
        resolved_ai_base_url=lambda: base_url,
    )
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


def _make_analyzer(config=None, metadata=None):
    logger = Mock()
    analyzer = AIAnalyzer(config or _config(), logger, metadata)
    return analyzer, logger


def _http_error(body, code=429):
    return HTTPError("https://api.example.test", code, "Too Many Requests", {}, io.BytesIO(body))


def test_enabled_is_false_when_ai_disabled():
    analyzer, _ = _make_analyzer(_config(ai_enabled=False))
    assert analyzer.enabled is False


def test_enabled_is_false_without_api_key():
    analyzer, _ = _make_analyzer(_config(ai_api_key=""))
    assert analyzer.enabled is False


def test_enabled_is_true_when_fully_configured():
    analyzer, _ = _make_analyzer(_config(ai_enabled=True, ai_api_key="sk-live"))
    assert analyzer.enabled is True


def test_enabled_falls_back_to_legacy_gemini_settings():
    cfg = SimpleNamespace(
        gemini_enabled=True,
        gemini_api_key="gemini-legacy-key",
        gemini_model="gemini-legacy-model",
    )
    analyzer, _ = _make_analyzer(cfg)

    assert analyzer.enabled is True
    assert analyzer.provider == "gemini"
    assert analyzer.api_key == "gemini-legacy-key"
    assert analyzer.model == "gemini-legacy-model"
    assert analyzer.base_url == "https://generativelanguage.googleapis.com/v1beta/models"


@pytest.mark.parametrize("limit", [0, -1])
def test_rate_limit_disabled_for_nonpositive_limit(limit):
    analyzer, _ = _make_analyzer(_config(ai_rate_limit_per_minute=limit))

    for _ in range(5):
        assert analyzer._is_rate_limited() is False
    assert analyzer._request_history == []


def test_rate_limit_sliding_window_prunes_expired_entries(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(analyzer_module.time, "monotonic", lambda: clock[0])
    analyzer, _ = _make_analyzer(_config(ai_rate_limit_per_minute=2))

    assert analyzer._is_rate_limited() is False
    clock[0] += 10
    assert analyzer._is_rate_limited() is False
    assert analyzer._is_rate_limited() is True
    assert len(analyzer._request_history) == 2

    clock[0] += 50
    assert analyzer._is_rate_limited() is False
    assert len(analyzer._request_history) == 2

    clock[0] += 10
    assert analyzer._is_rate_limited() is False
    assert len(analyzer._request_history) == 2


def test_extract_text_dispatches_on_provider():
    gemini, _ = _make_analyzer(_config(provider="gemini"))
    anthropic, _ = _make_analyzer(_config(provider="anthropic"))
    openai, _ = _make_analyzer(_config(provider="openai"))

    gemini_response = {"candidates": [{"content": {"parts": [{"text": "gemini"}]}}]}
    claude_response = {"content": [{"type": "text", "text": "claude"}]}
    openai_response = {"choices": [{"message": {"content": "openai"}}]}

    assert gemini._extract_text(gemini_response) == "gemini"
    assert anthropic._extract_text(claude_response) == "claude"
    assert openai._extract_text(openai_response) == "openai"


def test_extract_text_helpers_reject_wrong_container_types():
    assert AIAnalyzer._extract_gemini_text({"candidates": "nope"}) == ""
    assert AIAnalyzer._extract_gemini_text({"candidates": [{"content": {"parts": "nope"}}]}) == ""
    assert AIAnalyzer._extract_claude_text({"content": "nope"}) == ""
    assert AIAnalyzer._extract_openai_text({"choices": "nope"}) == ""


def test_build_request_gemini_body_and_headers():
    analyzer, _ = _make_analyzer(
        _config(
            provider="gemini",
            model="gemini-1.5-flash",
            base_url="https://generativelanguage.googleapis.com/v1beta/models/",
            ai_api_key="gemini-key",
        )
    )

    req = analyzer._build_request({"metric": "cpu"})

    assert req.full_url == (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-1.5-flash:generateContent?key=gemini-key"
    )
    assert req.get_method() == "POST"
    assert req.headers["X-goog-api-key"] == "gemini-key"
    assert req.headers["Content-type"] == "application/json; charset=utf-8"
    body = json.loads(req.data.decode("utf-8"))
    assert body["systemInstruction"]["parts"][0]["text"] == analyzer.system_instruction
    assert body["contents"][0]["role"] == "user"
    assert json.loads(body["contents"][0]["parts"][0]["text"]) == {"metric": "cpu"}
    assert body["generationConfig"] == {"maxOutputTokens": 256, "temperature": 0.2}


def test_build_request_anthropic_body_and_headers():
    analyzer, _ = _make_analyzer(
        _config(
            provider="anthropic",
            model="claude-3-5-haiku-20241022",
            base_url="https://api.anthropic.com/v1",
            ai_api_key="sk-ant-key",
        )
    )

    req = analyzer._build_request({"metric": "cpu"})

    assert req.full_url == "https://api.anthropic.com/v1/messages"
    assert req.headers["X-api-key"] == "sk-ant-key"
    assert req.headers["Anthropic-version"] == "2023-06-01"
    body = json.loads(req.data.decode("utf-8"))
    assert body["model"] == "claude-3-5-haiku-20241022"
    assert body["system"] == analyzer.system_instruction
    assert body["max_tokens"] == 256
    assert body["temperature"] == 0.2
    assert json.loads(body["messages"][0]["content"]) == {"metric": "cpu"}


@pytest.mark.parametrize(
    "provider,base_url,model",
    [
        ("deepseek", "https://api.deepseek.com/v1", "deepseek-chat"),
        ("openai", "https://api.openai.com/v1", "gpt-4o-mini"),
        ("groq", "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
    ],
)
def test_build_request_openai_compatible_body_and_headers(provider, base_url, model):
    analyzer, _ = _make_analyzer(
        _config(provider=provider, model=model, base_url=base_url, ai_api_key="sk-key")
    )

    req = analyzer._build_request({"metric": "cpu"})

    assert req.full_url == f"{base_url}/chat/completions"
    assert req.headers["Authorization"] == "Bearer sk-key"
    body = json.loads(req.data.decode("utf-8"))
    assert body["model"] == model
    assert body["max_tokens"] == 256
    assert [message["role"] for message in body["messages"]] == ["system", "user"]
    assert body["messages"][0]["content"] == analyzer.system_instruction
    assert json.loads(body["messages"][1]["content"]) == {"metric": "cpu"}


def test_build_request_custom_base_url_strips_trailing_slash():
    analyzer, _ = _make_analyzer(
        _config(
            provider="custom",
            model="internal-model",
            base_url="https://llm.internal.example/api/v1/",
        )
    )

    req = analyzer._build_request({"metric": "cpu"})

    assert req.full_url == "https://llm.internal.example/api/v1/chat/completions"
    body = json.loads(req.data.decode("utf-8"))
    assert body["model"] == "internal-model"


@pytest.mark.parametrize(
    "provider,base_url,response,expected",
    [
        (
            "gemini",
            "https://generativelanguage.googleapis.com/v1beta/models",
            {"candidates": [{"content": {"parts": [{"text": "gemini text"}]}}]},
            "gemini text",
        ),
        (
            "anthropic",
            "https://api.anthropic.com/v1",
            {"content": [{"type": "text", "text": "claude text"}]},
            "claude text",
        ),
        (
            "openai",
            "https://api.openai.com/v1",
            {"choices": [{"message": {"content": "openai text"}}]},
            "openai text",
        ),
    ],
)
def test_analyze_returns_provider_shaped_text(provider, base_url, response, expected):
    analyzer, _ = _make_analyzer(_config(provider=provider, model="test-model", base_url=base_url))
    fake = _FakeResponse(json.dumps(response).encode("utf-8"))

    with patch("server_agent.ai.analyzer.urlopen", return_value=fake) as mocked:
        assert analyzer.analyze(_incident()) == expected

    mocked.assert_called_once()
    assert mocked.call_args.kwargs["timeout"] == 7
    assert mocked.call_args.kwargs["context"] is analyzer.ssl_context


def test_analyze_payload_includes_context_and_sanitizes_secrets():
    metadata = ServerMetadata(
        os_name="Ubuntu",
        os_version="22.04",
        panel="cPanel",
        web_server="Nginx",
        database="MySQL",
        firewall="UFW",
    )
    analyzer, _ = _make_analyzer(_config(), metadata)
    incident = _incident(
        details={"db_password": "hunter2", "note": "token=abc"},
        evidence="password=supersecret\nload=9",
    )
    captured = {}

    def fake_urlopen(request, timeout, context):
        captured["request"] = request
        captured["timeout"] = timeout
        captured["context"] = context
        return _FakeResponse(
            json.dumps({"choices": [{"message": {"content": "Likely cause: CPU"}}]}).encode("utf-8")
        )

    with patch("server_agent.ai.analyzer.urlopen", side_effect=fake_urlopen):
        assert analyzer.analyze(incident) == "Likely cause: CPU"

    assert captured["timeout"] == 7
    body = json.loads(captured["request"].data.decode("utf-8"))
    payload = json.loads(body["messages"][1]["content"])
    assert payload["server"] == "srv-1"
    assert payload["environment"] == "production"
    assert payload["incident"]["fingerprint"] == "cpu:test"
    assert payload["server_context"] == {
        "os": "Ubuntu 22.04",
        "panel": "cPanel",
        "web_stack": "Nginx",
        "database": "MySQL",
        "firewall": "UFW",
    }
    assert payload["incident"]["details"]["db_password"] == "[REDACTED]"
    assert payload["incident"]["details"]["note"] == "token=[REDACTED]"
    assert "supersecret" not in payload["incident_evidence_logs"]
    assert payload["incident_evidence_logs"] == "password=[REDACTED]\nload=9"


def test_analyze_payload_omits_optional_context_when_unset():
    analyzer, _ = _make_analyzer()
    captured = {}

    def fake_urlopen(request, timeout, context):
        captured["request"] = request
        return _FakeResponse(
            json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode("utf-8")
        )

    with patch("server_agent.ai.analyzer.urlopen", side_effect=fake_urlopen):
        assert analyzer.analyze(_incident()) == "ok"

    body = json.loads(captured["request"].data.decode("utf-8"))
    payload = json.loads(body["messages"][1]["content"])
    assert "server_context" not in payload
    assert "incident_evidence_logs" not in payload


def test_analyze_truncates_response_text_to_4000_chars():
    analyzer, _ = _make_analyzer()
    response = {"choices": [{"message": {"content": "x" * 4100}}]}

    with patch(
        "server_agent.ai.analyzer.urlopen",
        return_value=_FakeResponse(json.dumps(response).encode("utf-8")),
    ):
        result = analyzer.analyze(_incident())

    assert len(result) == 4000
    assert result == "x" * 4000


def test_analyze_non_dict_response_returns_empty_and_warns():
    analyzer, logger = _make_analyzer()

    with patch(
        "server_agent.ai.analyzer.urlopen",
        return_value=_FakeResponse(b"[]"),
    ):
        assert analyzer.analyze(_incident()) == ""

    logger.warning.assert_called_once()
    assert logger.warning.call_args.args[0] == "%s API returned an invalid response"


@pytest.mark.parametrize(
    "body,expected",
    [
        (b'{"error":{"message":"quota exceeded"}}', "quota exceeded"),
        (b'{"error":"string failure"}', "string failure"),
        (b'{"message":"top level message"}', "top level message"),
        (b'{"unexpected":true}', '{"unexpected":true}'),
    ],
)
def test_analyze_http_error_logs_parsed_message(body, expected):
    analyzer, logger = _make_analyzer()

    with patch("server_agent.ai.analyzer.urlopen", side_effect=_http_error(body)):
        assert analyzer.analyze(_incident()) == ""

    logger.warning.assert_called_once()
    args = logger.warning.call_args.args
    assert args[0] == "%s API returned HTTP %s: %s"
    assert args[2] == 429
    assert expected in args[3]


@pytest.mark.parametrize(
    "body",
    [b"not json at all", b"<html>gateway error</html>"],
)
def test_analyze_http_error_with_unparsed_body_logs_status_only(body):
    analyzer, logger = _make_analyzer()

    with patch("server_agent.ai.analyzer.urlopen", side_effect=_http_error(body, code=502)):
        assert analyzer.analyze(_incident()) == ""

    logger.warning.assert_called_once()
    args = logger.warning.call_args.args
    assert args[0] == "%s API returned HTTP %s"
    assert args[2] == 502


def test_analyze_http_error_with_unreadable_body_returns_empty():
    analyzer, logger = _make_analyzer()
    error = HTTPError("https://api.example.test", 500, "Server Error", {}, _ExplodingBody())

    with patch("server_agent.ai.analyzer.urlopen", side_effect=error):
        assert analyzer.analyze(_incident()) == ""

    logger.warning.assert_called_once()
    assert logger.warning.call_args.args[0] == "%s API returned HTTP %s"


@pytest.mark.parametrize(
    "error",
    [
        URLError("connection refused"),
        TimeoutError("timed out"),
        json.JSONDecodeError("Expecting value", "not-json", 0),
        OSError("socket closed"),
    ],
)
def test_analyze_transport_errors_return_empty(error):
    analyzer, logger = _make_analyzer()

    with patch("server_agent.ai.analyzer.urlopen", side_effect=error):
        assert analyzer.analyze(_incident()) == ""

    logger.warning.assert_called_once()
    assert logger.warning.call_args.args[0] == "%s analysis failed: %s"


def test_analyze_rate_limited_skips_urlopen():
    analyzer, logger = _make_analyzer(_config(ai_rate_limit_per_minute=1))
    assert analyzer._is_rate_limited() is False

    with patch("server_agent.ai.analyzer.urlopen") as mocked:
        assert analyzer.analyze(_incident()) == ""

    mocked.assert_not_called()
    logger.warning.assert_called_once()
    assert "rate limit exceeded" in logger.warning.call_args.args[0]


@pytest.mark.parametrize("overrides", [{"ai_enabled": False}, {"ai_api_key": ""}])
def test_disabled_analyzer_returns_empty_without_request(overrides):
    analyzer, logger = _make_analyzer(_config(**overrides))

    with patch("server_agent.ai.analyzer.urlopen") as mocked:
        assert analyzer.analyze(_incident()) == ""

    mocked.assert_not_called()
    logger.warning.assert_not_called()


def test_set_metadata_updates_system_instruction():
    analyzer, _ = _make_analyzer()
    assert "Target Server Environment" not in analyzer.system_instruction

    analyzer.set_metadata(
        ServerMetadata(os_name="Debian", os_version="12", os_family="debian", panel="Standalone")
    )

    assert "Debian 12" in analyzer.system_instruction


def test_close_is_a_repeatable_noop():
    analyzer, _ = _make_analyzer()

    assert analyzer.close() is None
    assert analyzer.close() is None


def test_extract_openai_text_handles_null_message():
    assert AIAnalyzer._extract_openai_text({"choices": [{"message": None}]}) == ""


def test_analyze_returns_empty_on_invalid_utf8_response():
    logger = Mock()
    analyzer = AIAnalyzer(_config(), logger)
    with patch(
        "server_agent.ai.analyzer.urlopen",
        return_value=_FakeResponse(b"\xff\xfe\x00"),
    ):
        assert analyzer.analyze(_incident()) == ""
