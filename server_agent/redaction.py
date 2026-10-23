from __future__ import annotations

import re
from dataclasses import replace
from typing import Any, Dict, Tuple

from .models import Incident


REDACTED = "[REDACTED]"
_SENSITIVE_KEY = re.compile(
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth(?:orization)?|"
    r"password|passwd|pwd|secret|cookie|private[_-]?key|database[_-]?url|dsn)",
    re.IGNORECASE,
)
_URL_SECRET = re.compile(
    r"([?&](?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|"
    r"password|passwd|secret|signature|sig|key)=)[^&#\s]+",
    re.IGNORECASE,
)
_HEADER_SECRET = re.compile(
    r"(?im)^(\s*(?:authorization|cookie|set-cookie|x-api-key|x-auth-token)\s*:\s*)[^\r\n]+"
)
_ASSIGNMENT_SECRET = re.compile(
    r"(\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|"
    r"passwd|pwd|secret|cookie|private[_-]?key|database[_-]?url|dsn)\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]+")
_CONNECTION_PASSWORD = re.compile(
    r"((?:postgres(?:ql)?|mysql|mongodb|redis)://[^:\s/]+:)[^@\s]+(@)",
    re.IGNORECASE,
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL,
)


def sanitize_text(value: str) -> Tuple[str, bool]:
    """Remove common credentials while retaining useful operational context."""
    result = value
    result = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", result)
    result = _HEADER_SECRET.sub(r"\1" + REDACTED, result)
    result = _URL_SECRET.sub(r"\1" + REDACTED, result)
    result = _ASSIGNMENT_SECRET.sub(r"\1" + REDACTED, result)
    result = _BEARER.sub(r"\1" + REDACTED, result)
    result = _CONNECTION_PASSWORD.sub(r"\1" + REDACTED + r"\2", result)
    return result, result != value


def sanitize_value(value: Any, key: str = "") -> Tuple[Any, bool]:
    if _SENSITIVE_KEY.search(key):
        return REDACTED, True
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, dict):
        clean: Dict[Any, Any] = {}
        changed = False
        for item_key, item_value in value.items():
            safe_value, was_changed = sanitize_value(item_value, str(item_key))
            clean[item_key] = safe_value
            changed = changed or was_changed
        return clean, changed
    if isinstance(value, list):
        clean_list = []
        changed = False
        for item in value:
            safe_value, was_changed = sanitize_value(item)
            clean_list.append(safe_value)
            changed = changed or was_changed
        return clean_list, changed
    if isinstance(value, tuple):
        clean_tuple = []
        changed = False
        for item in value:
            safe_value, was_changed = sanitize_value(item)
            clean_tuple.append(safe_value)
            changed = changed or was_changed
        return tuple(clean_tuple), changed
    return value, False


def sanitize_incident(incident: Incident) -> Incident:
    """Return a safe copy for third-party AI and notification transports."""
    title, _ = sanitize_text(incident.title)
    summary, _ = sanitize_text(incident.summary)
    details, _ = sanitize_value(incident.details)
    analysis, _ = sanitize_text(incident.ai_analysis)
    return replace(
        incident,
        title=title,
        summary=summary,
        details=details,
        ai_analysis=analysis,
    )
