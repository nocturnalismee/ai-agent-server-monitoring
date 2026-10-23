from server_agent.models import Incident
from server_agent.redaction import REDACTED, sanitize_incident, sanitize_text


def test_redacts_credentials_but_retains_log_context():
    source = (
        "upstream failed for user=alice password=hunter2 "
        "Authorization: Bearer abc.def.ghi\n"
        "GET /api?token=abc123&request_id=keep-me"
    )
    result, changed = sanitize_text(source)
    assert changed
    assert "hunter2" not in result
    assert "abc.def.ghi" not in result
    assert "abc123" not in result
    assert "upstream failed" in result
    assert "request_id=keep-me" in result
    assert REDACTED in result


def test_redacts_sensitive_detail_values_recursively():
    incident = Incident(
        kind="web",
        severity="WARNING",
        title="Web error",
        summary="Database error",
        fingerprint="web:test",
        details={
            "raw_log": "mysql://agent:password123@db.internal/app",
            "api_key": "do-not-send",
            "samples": ["Cookie: session=secret-session"],
        },
    )
    safe = sanitize_incident(incident)
    assert safe is not incident
    assert "password123" not in safe.details["raw_log"]
    assert safe.details["api_key"] == REDACTED
    assert "secret-session" not in safe.details["samples"][0]
    assert incident.details["api_key"] == "do-not-send"
