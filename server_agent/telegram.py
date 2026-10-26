from __future__ import annotations

import html
import json
from datetime import datetime
from typing import Any, Dict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

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





class TelegramNotifier:
    """Send structured alerts using Telegram's HTTPS Bot API (HTML mode)."""

    _MAX_MESSAGE_LENGTH = 4096

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger

    @staticmethod
    def _short_name(server_name: str) -> str:
        """Return the first label of the hostname (e.g. 'app' from 'app.domain.id')."""
        return server_name.split(".")[0] if server_name else server_name

    def _message(self, incident) -> str:
        sev = incident.severity.upper()
        emoji = _SEVERITY_EMOJI.get(sev, "⚪")
        short = self._short_name(self.cfg.server_name)

        # ── Header: emoji + short hostname + severity + title ─────
        lines = [
            f"{emoji} <b>[{_e(short)}] {_e(sev)}: {_e(incident.title)}</b>",
            "",
        ]

        # ── Server info (plain formatted lines, no <pre>) ─────────
        ts = _fmt_timestamp(incident.timestamp)
        lines += [
            f"🖥 <b>{_e(self.cfg.server_name)}</b>  ·  {_e(self.cfg.environment)}  ·  {_e(ts)}",
            "",
        ]

        # ── Summary ───────────────────────────────────────────────
        if incident.summary:
            lines += [
                f"📋 <b>Summary</b>",
                f"<code>{_e(incident.summary)}</code>",
                "",
            ]

        # ── Details (key: value pairs, no <pre>) ──────────────────
        if incident.details:
            detail_lines = "  |  ".join(
                f"<b>{_e(k.upper())}</b>: {_e(v) if v not in ('', None) else '—'}"
                for k, v in incident.details.items()
            )
            lines += [
                f"🔍 <b>Details</b>",
                detail_lines,
                "",
            ]

        # ── AI Analysis ───────────────────────────────────────────
        if incident.ai_analysis:
            lines += [
                "🤖 <b>AI Analysis</b>",
                f"<code>{_e(incident.ai_analysis)}</code>",
                "",
            ]

        # ── Footer ────────────────────────────────────────────────
        lines.append(f"<i>{_e(self.cfg.server_name)} · {_e(self.cfg.environment)}</i>")

        message = "\n".join(lines)
        if len(message) > self._MAX_MESSAGE_LENGTH:
            message = message[: self._MAX_MESSAGE_LENGTH - 32] + "\n…<i>[truncated]</i>"
        return message


    def _payload(self, incident) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "chat_id": self.cfg.telegram_chat_id,
            "text": self._message(incident),
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if self.cfg.telegram_message_thread_id is not None:
            payload["message_thread_id"] = self.cfg.telegram_message_thread_id
        return payload

    def send(self, incident) -> bool:
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
        from .models import Incident

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

