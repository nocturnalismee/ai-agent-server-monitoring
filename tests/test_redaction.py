import pytest

from server_agent.models import Incident
from server_agent.redaction import (
    REDACTED,
    sanitize_incident,
    sanitize_text,
    sanitize_value,
)


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


@pytest.mark.parametrize(
    "source,secret",
    [
        ("mongodb+srv://app:Secret@cluster.example/db", "Secret"),
        ("https://admin:s3cret@internal.example/path", "s3cret"),
        ("postgresql://agent:password123@db.internal/app", "password123"),
        ("redis://default:r3dispass@cache:6379/0", "r3dispass"),
    ],
)
def test_redacts_connection_password_for_any_scheme(source, secret):
    result, changed = sanitize_text(source)
    assert changed
    assert secret not in result
    assert REDACTED in result


def test_redacts_cookie_header_mid_line_without_leaving_session_id():
    result, changed = sanitize_text("< Set-Cookie: PHPSESSID=abc123def456; path=/")
    assert changed
    assert "abc123" not in result
    assert "def456" not in result
    assert "abc123def456" not in result
    assert "Set-Cookie" in result
    assert REDACTED in result


def test_redacts_authorization_header_inside_command_line():
    result, changed = sanitize_text('curl -H "Authorization: Basic dXNlcjpwYXNz" https://x.test')
    assert changed
    assert "dXNlcjpwYXNz" not in result
    assert "Authorization" in result
    assert REDACTED in result


@pytest.mark.parametrize(
    "source,secret",
    [
        ("x-api-key: sk-abc123secret", "sk-abc123secret"),
        ("X-Auth-Token: token-value-123", "token-value-123"),
        ("Proxy-Authorization: Basic cHJveHk6c2VjcmV0", "cHJveHk6c2VjcmV0"),
        ("Cookie: session=secret-session", "secret-session"),
    ],
)
def test_redacts_other_sensitive_headers_mid_line(source, secret):
    result, changed = sanitize_text(source)
    assert changed
    assert secret not in result
    assert REDACTED in result


def test_header_redaction_does_not_consume_following_line():
    result, _ = sanitize_text("Set-Cookie: PHPSESSID=abc123; path=/\nnext line stays")
    assert "abc123" not in result
    assert "next line stays" in result


@pytest.mark.parametrize(
    "source,secret",
    [
        ('{"password": "hunter2"}', "hunter2"),
        ('db_pass="Sup3rSecret"', "Sup3rSecret"),
        ("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalr"),
        ("aws_access_key_id = ZZZZNOTAREALKEY", "ZZZZNOTAREALKEY"),
        ("passphrase='correcthorse'", "correcthorse"),
        ("credential=credvalue", "credvalue"),
        ("session=sessvalue", "sessvalue"),
        ("secret_key=skvalue", "skvalue"),
        ("client_secret=csvalue", "csvalue"),
    ],
)
def test_redacts_additional_assignment_keywords(source, secret):
    result, changed = sanitize_text(source)
    assert changed
    assert secret not in result
    assert REDACTED in result


def test_assignment_redaction_keeps_unrelated_keys():
    result, _ = sanitize_text("user=alice request_id=keep-me compass=North")
    assert "user=alice" in result
    assert "request_id=keep-me" in result
    assert "compass=North" in result


def test_redacts_truncated_private_key_through_end_of_text():
    source = "before -----BEGIN RSA PRIVATE KEY-----\nMIIEsecretmaterial\nno end marker"
    result, changed = sanitize_text(source)
    assert changed
    assert "MIIEsecretmaterial" not in result
    assert "no end marker" not in result
    assert "before" in result


def test_redacts_complete_private_key_block():
    source = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----"
    result, changed = sanitize_text(source)
    assert changed
    assert "MIIEabc" not in result
    assert result == "[REDACTED PRIVATE KEY]"


@pytest.mark.parametrize(
    "token",
    [
        "sk_live_1234567890abcdefghij",
        "AIza" + "A" * 35,
    ],
)
def test_redacts_stripe_and_google_api_tokens(token):
    result, changed = sanitize_text("key=" + token)
    assert changed
    assert token not in result
    assert "REDACTED" in result


def test_sanitize_incident_redacts_fingerprint():
    incident = Incident(
        kind="ssh",
        severity="CRITICAL",
        title="Auth failure",
        summary="failed",
        fingerprint="auth:token=supersecret",
    )
    safe = sanitize_incident(incident)
    assert "supersecret" not in safe.fingerprint
    assert REDACTED in safe.fingerprint
    assert incident.fingerprint == "auth:token=supersecret"


@pytest.mark.parametrize(
    "source,secret",
    [
        ('{"Authorization": "Basic dXNlcjpwYXNz"}', "dXNlcjpwYXNz"),
        ('{"Proxy-Authorization": "Basic cHJveHk6c2VjcmV0"}', "cHJveHk6c2VjcmV0"),
    ],
)
def test_redacts_json_encoded_auth_headers(source, secret):
    result, changed = sanitize_text(source)
    assert changed
    assert secret not in result
    assert "Authorization" in result
    assert result.endswith("}")
    assert REDACTED in result


@pytest.mark.parametrize(
    "key",
    ["db_pass", "session", "credential", "passphrase", "aws_access_key_id"],
)
def test_redacts_expanded_sensitive_detail_keys(key):
    value, changed = sanitize_value("structured-secret", key)
    assert changed
    assert value == REDACTED


def test_sanitize_incident_redacts_expanded_sensitive_detail_keys():
    incident = Incident(
        kind="health",
        severity="WARNING",
        title="Test",
        summary="Test",
        fingerprint="test",
        details={
            "db_pass": "db-secret",
            "session": "session-secret",
            "credential": "credential-secret",
            "passphrase": "passphrase-secret",
            "aws_access_key_id": "aws-key-secret",
        },
    )
    safe = sanitize_incident(incident)
    for key in incident.details:
        assert safe.details[key] == REDACTED
        assert incident.details[key] != REDACTED


def test_redacts_connection_password_with_empty_username():
    result, changed = sanitize_text("redis://:onlypass@host:6379/0")
    assert changed
    assert "onlypass" not in result
    assert REDACTED in result


def test_redacts_assignment_value_with_escaped_quotes():
    source = '{"password":"a\\"bSECRET"}'
    result, changed = sanitize_text(source)
    assert changed
    assert "bSECRET" not in result
    assert result.endswith("}")


def test_bare_hex_string_without_context_is_not_redacted():
    source = "checksum " + "0123456789abcdef" * 2
    result, changed = sanitize_text(source)
    assert changed is False
    assert result == source
