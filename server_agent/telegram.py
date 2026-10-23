from __future__ import annotations

import json
from typing import Any, Dict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class TelegramNotifier:
    """Send structured alerts using Telegram's HTTPS Bot API."""

    _MAX_MESSAGE_LENGTH = 4096

    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger

    def _message(self, incident) -> str:
        details = "\n".join(
            f"- {key}: {value}" for key, value in incident.details.items()
        ) or "- none"
        message = (
            "SERVER MONITOR ALERT\n"
            f"Severity: {incident.severity}\n"
            f"Server: {self.cfg.server_name}\n"
            f"Environment: {self.cfg.environment}\n"
            f"Time (UTC): {incident.timestamp}\n\n"
            f"{incident.title}\n"
            f"{incident.summary}\n\n"
            f"Details:\n{details}"
        )
        if incident.ai_analysis:
            message += f"\n\nAI analysis:\n{incident.ai_analysis}"
        if len(message) > self._MAX_MESSAGE_LENGTH:
            message = message[: self._MAX_MESSAGE_LENGTH - 16] + "\n[truncated]"
        return message

    def _payload(self, incident) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "chat_id": self.cfg.telegram_chat_id,
            "text": self._message(incident),
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
                description = data.get("description", "unknown error") if isinstance(data, dict) else "invalid response"
                self.logger.error("Telegram API rejected alert: %s", description)
                return False
            self.logger.info("Telegram alert sent: severity=%s title=%s", incident.severity, incident.title)
            return True
        except HTTPError as exc:
            self.logger.error("Telegram API returned HTTP %s", exc.code)
        except (URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            self.logger.error("Telegram alert delivery failed: %s", exc)
        return False

    def send_test(self) -> bool:
        from .models import Incident

        return self.send(Incident(
            kind="test",
            severity="INFO",
            title="Server AI Agent test",
            summary="Telegram notification configuration is working.",
            fingerprint="test",
            details={"status": "ok", "transport": "telegram"},
        ))
