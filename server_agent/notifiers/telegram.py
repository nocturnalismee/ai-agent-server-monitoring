from __future__ import annotations

import html
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..core.models import Incident, ServerMetadata
from .base import BaseNotifier

# Severity → emoji indicator
_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "WARNING":  "🟡",
    "INFO":     "🟢",
    "RECOVERY": "✅",
}


def _e(text: object) -> str:
    """Escape a value for Telegram HTML parse_mode."""
    return html.escape(str(text) if text is not None else "")


def _fmt_timestamp(ts: str) -> str:
    """Convert ISO timestamp to a readable string."""
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return ts


def _format_card(items: List[Tuple[str, str]]) -> str:
    """Format key-value pairs into a clean monospace card with aligned colons."""
    if not items:
        return ""
    max_k = max(len(k) for k, _ in items)
    lines = [f"{k.ljust(max_k)} : {v}" for k, v in items]
    return "<pre>" + html.escape("\n".join(lines)) + "</pre>"


def _format_ai_text(raw_text: str) -> str:
    """Format AI output cleanly with bold section headers and copyable code blocks."""
    if not raw_text:
        return ""

    escaped = html.escape(raw_text.strip())

    # Format inline backticks `cmd` -> <code>cmd</code>
    formatted = re.sub(r"`([^`\n]+)`", r"<code>\1</code>", escaped)

    # Format bold markdown **Header:** -> <b>Header:</b>
    formatted = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", formatted)

    # Format section headers like "Likely cause:", "Immediate checks:", etc. into bold
    for header in (
        "Likely cause:",
        "Immediate checks:",
        "Immediate checks (read-only):",
        "Recommended fix:",
        "Risk:",
        "Risk Assessment:",
        "Next step:",
    ):
        pattern = rf"(?m)^({re.escape(header)})"
        formatted = re.sub(pattern, r"<b>\1</b>", formatted)

    return formatted


# Tags understood by Telegram's HTML parse_mode (used to re-balance on truncation).
_HTML_TAG_RE = re.compile(r"<(/?)(b|i|code|pre|a|u|s)(?:\s[^>]*)?>", re.IGNORECASE)


def _utf16_len(text: str) -> int:
    """Telegram enforces its 4096 limit in UTF-16 code units, not code points."""
    return len(text.encode("utf-16-le")) // 2


def _close_open_tags(text: str) -> str:
    """Return closing tags for any HTML tags still open in ``text``."""
    stack: List[str] = []
    for match in _HTML_TAG_RE.finditer(text):
        closing, name = match.group(1), match.group(2).lower()
        if closing:
            if name in stack:
                while stack:
                    if stack.pop() == name:
                        break
        else:
            stack.append(name)
    return "".join(f"</{name}>" for name in reversed(stack))


def _truncate_html(text: str, limit: int) -> str:
    """Truncate ``text`` to ``limit`` UTF-16 units without breaking HTML or emoji.

    Telegram rejects a message outright (HTTP 400) when parse_mode HTML contains
    unbalanced tags, so the result is always re-balanced before the marker is
    appended. Surrogate pairs are never split.
    """
    if _utf16_len(text) <= limit:
        return text

    suffix = "\n…<i>[truncated]</i>"
    budget = limit - _utf16_len(suffix)
    if budget <= 0:
        return suffix[-limit:] if limit > 0 else ""

    total = 0
    cut = len(text)
    for index, char in enumerate(text):
        width = 2 if ord(char) > 0xFFFF else 1
        if total + width > budget:
            cut = index
            break
        total += width

    head = text[:cut]
    newline = head.rfind("\n")
    if newline > 0:
        head = head[:newline]

    def assemble(prefix: str) -> str:
        # Drop an incomplete tag at the cut boundary before re-balancing.
        if prefix.rfind("<") > prefix.rfind(">"):
            prefix = prefix[: prefix.rfind("<")]
        return prefix + _close_open_tags(prefix) + suffix

    result = assemble(head)
    while _utf16_len(result) > limit and head:
        head = head[:-1]
        result = assemble(head)
    return result


class TelegramNotifier(BaseNotifier):
    """Send structured alerts using Telegram's HTTPS Bot API (HTML mode)."""

    _MAX_MESSAGE_LENGTH = 4096

    def __init__(self, config, logger, metadata: Optional[ServerMetadata] = None):
        super().__init__(config, logger, metadata)

    @staticmethod
    def _short_name(server_name: str) -> str:
        """Return the first label of the hostname (e.g. 'app' from 'app.domain.id')."""
        return server_name.split(".")[0] if server_name else server_name

    def _message(self, incident: Incident) -> str:
        sev = incident.severity.upper()
        emoji = _SEVERITY_EMOJI.get(sev, "⚪")
        short = self._short_name(self.cfg.server_name)

        # ── Header: emoji + short hostname + severity + title ─────
        lines = [
            f"{emoji} <b>[{_e(short)}] {_e(sev)}: {_e(incident.title)}</b>",
            "",
        ]

        # ── Server info box (aligned card) ───────────────────────
        ts = _fmt_timestamp(incident.timestamp)
        server_card_items = [
            ("SERVER", self.cfg.server_name),
        ]
        if self.metadata and self.metadata.badge():
            server_card_items.append(("STACK", self.metadata.badge()))
        else:
            server_card_items.append(("PROFILE", self.cfg.environment))
        server_card_items.append(("TIME", ts))

        lines += [
            _format_card(server_card_items),
            "",
        ]

        # ── Summary ───────────────────────────────────────────────
        if incident.summary:
            lines += [
                "📋 <b>Summary</b>",
                f"<code>{_e(incident.summary)}</code>",
                "",
            ]

        # ── Details box (aligned card) ────────────────────────────
        if incident.details:
            detail_items = []
            raw_log = None

            for k, v in incident.details.items():
                if k.lower() in ("raw_log", "raw log", "log"):
                    raw_log = str(v)
                    continue
                k_name = str(k).upper().replace("_", " ")[:15]
                v_str = str(v) if v not in ("", None) else "—"
                detail_items.append((k_name, v_str))

            if detail_items:
                lines += [
                    "🔍 <b>Details</b>",
                    _format_card(detail_items),
                    "",
                ]

            if raw_log:
                lines += [
                    "📝 <b>Log Record</b>",
                    f"<code>{_e(raw_log)}</code>",
                    "",
                ]

        # ── AI Analysis & Troubleshooting ─────────────────────────
        if incident.ai_analysis:
            formatted_ai = _format_ai_text(incident.ai_analysis)
            lines += [
                "🤖 <b>AI Diagnosis & Troubleshooting</b>",
                formatted_ai,
                "",
            ]

        # ── Footer ────────────────────────────────────────────────
        lines.append(f"<i>{_e(self.cfg.server_name)} · {_e(self.cfg.environment)}</i>")

        message = "\n".join(lines)
        return _truncate_html(message, self._MAX_MESSAGE_LENGTH)

    def _payload(self, incident: Incident) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "chat_id": self.cfg.telegram_chat_id,
            "text": self._message(incident),
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if self.cfg.telegram_message_thread_id is not None:
            payload["message_thread_id"] = self.cfg.telegram_message_thread_id
        # Low-severity notifications should not wake anyone up; explicit tests
        # are always delivered with sound so the operator can confirm delivery.
        if incident.severity.upper() in {"INFO", "RECOVERY"} and incident.kind != "test":
            payload["disable_notification"] = True
        return payload

    def send(self, incident: Incident) -> bool:
        body = json.dumps(self._payload(incident), ensure_ascii=False).encode("utf-8")
        request = Request(
            f"https://api.telegram.org/bot{self.cfg.telegram_bot_token}/sendMessage",
            data=body,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.cfg.telegram_timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
            if not isinstance(data, dict) or not data.get("ok"):
                description = (
                    data.get("description", "unknown error")
                    if isinstance(data, dict)
                    else "invalid response"
                )
                self.logger.error("Telegram API rejected alert: %s", description)
                return False
            self.logger.info(
                "Telegram alert sent: severity=%s title=%s",
                incident.severity,
                incident.title,
            )
            return True
        except HTTPError as exc:
            self.logger.error("Telegram API returned HTTP %s", exc.code)
        except (URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            self.logger.error("Telegram alert delivery failed: %s", exc)
        return False

    def send_test(self) -> bool:
        return self.send(
            Incident(
                kind="test",
                severity="INFO",
                title="Server AI Agent test",
                summary="Telegram notification configuration is working correctly.",
                fingerprint="test",
                details={"status": "ok", "transport": "telegram"},
            )
        )
