from __future__ import annotations

import json
import ssl
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..core.models import Incident, ServerMetadata
from ..core.redaction import sanitize_incident
from .prompts import build_system_instruction


class AIAnalyzer:
    """Multi-provider AI enrichment via HTTPS REST API and Python stdlib.

    Supports:
      - deepseek (https://api.deepseek.com/v1)
      - openai (https://api.openai.com/v1)
      - claude / anthropic (https://api.anthropic.com/v1)
      - groq (https://api.groq.com/openai/v1)
      - kimi / moonshot (https://api.moonshot.cn/v1)
      - openrouter (https://openrouter.ai/api/v1)
      - custom / openai_compatible (any custom base URL)
      - gemini (Google Generative Language REST API)
    """

    def __init__(self, config, logger, metadata: Optional[ServerMetadata] = None):
        self.cfg = config
        self.logger = logger
        self.metadata = metadata
        self.enabled = bool(
            getattr(config, "ai_enabled", getattr(config, "gemini_enabled", False))
            and (getattr(config, "ai_api_key", "") or getattr(config, "gemini_api_key", ""))
        )
        self.provider = getattr(config, "ai_provider", "gemini").lower()
        self.api_key = getattr(config, "ai_api_key", getattr(config, "gemini_api_key", ""))
        self.model = (
            config.resolved_ai_model()
            if hasattr(config, "resolved_ai_model")
            else getattr(config, "gemini_model", "gemini-1.5-flash")
        )
        self.base_url = (
            config.resolved_ai_base_url()
            if hasattr(config, "resolved_ai_base_url")
            else "https://generativelanguage.googleapis.com/v1beta/models"
        )
        self.timeout = getattr(config, "ai_timeout_seconds", getattr(config, "gemini_timeout_seconds", 10))
        self.max_tokens = getattr(config, "ai_max_output_tokens", getattr(config, "gemini_max_output_tokens", 400))
        self.rate_limit = getattr(
            config, "ai_rate_limit_per_minute", getattr(config, "gemini_rate_limit_per_minute", 10)
        )

        self.ssl_context = ssl.create_default_context()
        self._rate_limit_lock = threading.Lock()
        self._request_history: List[float] = []

    def set_metadata(self, metadata: ServerMetadata) -> None:
        self.metadata = metadata

    @property
    def system_instruction(self) -> str:
        return build_system_instruction(self.metadata)

    def _is_rate_limited(self) -> bool:
        """Check sliding window (60s) rate limit. Return True if call should be blocked."""
        if self.rate_limit <= 0:
            return False
        now = time.monotonic()
        with self._rate_limit_lock:
            self._request_history = [
                ts for ts in self._request_history if now - ts < 60.0
            ]
            if len(self._request_history) >= self.rate_limit:
                return True
            self._request_history.append(now)
            return False

    @staticmethod
    def _extract_gemini_text(response: Dict[str, Any]) -> str:
        candidates = response.get("candidates", [])
        if not isinstance(candidates, list) or not candidates:
            return ""
        content = candidates[0].get("content", {}) if isinstance(candidates[0], dict) else {}
        parts = content.get("parts", []) if isinstance(content, dict) else []
        if not isinstance(parts, list):
            return ""
        return "".join(
            part.get("text", "") for part in parts
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        ).strip()

    @staticmethod
    def _extract_claude_text(response: Dict[str, Any]) -> str:
        content = response.get("content", [])
        if not isinstance(content, list):
            return ""
        return "".join(
            item.get("text", "") for item in content
            if isinstance(item, dict) and item.get("type") == "text"
        ).strip()

    @staticmethod
    def _extract_openai_text(response: Dict[str, Any]) -> str:
        choices = response.get("choices", [])
        if not isinstance(choices, list) or not choices:
            return ""
        first = choices[0] if isinstance(choices[0], dict) else {}
        message = first.get("message")
        if not isinstance(message, dict):
            return ""
        text = message.get("content", "")
        return text.strip() if isinstance(text, str) else ""

    def _extract_text(self, response: Dict[str, Any]) -> str:
        if self.provider == "gemini":
            return self._extract_gemini_text(response)
        if self.provider in {"claude", "anthropic"}:
            return self._extract_claude_text(response)
        return self._extract_openai_text(response)

    def _build_request(self, payload: Dict[str, Any]) -> Request:
        payload_json = json.dumps(payload, ensure_ascii=False)
        sys_instruction = self.system_instruction

        if self.provider == "gemini":
            url = f"{self.base_url.rstrip('/')}/{self.model}:generateContent?key={self.api_key}"
            body = {
                "systemInstruction": {"parts": [{"text": sys_instruction}]},
                "contents": [{"role": "user", "parts": [{"text": payload_json}]}],
                "generationConfig": {
                    "maxOutputTokens": self.max_tokens,
                    "temperature": 0.2,
                },
            }
            headers = {
                "Content-Type": "application/json; charset=utf-8",
                "x-goog-api-key": self.api_key,
            }
            return Request(
                url,
                data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                headers=headers,
                method="POST",
            )

        if self.provider in {"claude", "anthropic"}:
            url = f"{self.base_url.rstrip('/')}/messages"
            body = {
                "model": self.model,
                "system": sys_instruction,
                "messages": [{"role": "user", "content": payload_json}],
                "max_tokens": self.max_tokens,
                "temperature": 0.2,
            }
            headers = {
                "Content-Type": "application/json; charset=utf-8",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            }
            return Request(
                url,
                data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                headers=headers,
                method="POST",
            )

        # Default: OpenAI-compatible (DeepSeek, OpenAI, Groq, Kimi, OpenRouter, Custom)
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": sys_instruction},
                {"role": "user", "content": payload_json},
            ],
            "max_tokens": self.max_tokens,
            "temperature": 0.2,
        }
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {self.api_key}",
        }
        return Request(
            url,
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers=headers,
            method="POST",
        )

    def analyze(self, incident: Incident) -> str:
        if not self.enabled:
            return ""

        if self._is_rate_limited():
            self.logger.warning(
                "%s rate limit exceeded (%d requests/min); skipping AI enrichment for %s",
                self.provider.title(),
                self.rate_limit,
                incident.fingerprint,
            )
            return ""

        # Defense in depth: sanitize outbound telemetry
        safe_incident = sanitize_incident(incident)
        payload = {
            "server": self.cfg.server_name,
            "environment": self.cfg.environment,
            "incident": safe_incident.as_dict(),
        }
        if self.metadata:
            payload["server_context"] = {
                "os": f"{self.metadata.os_name} {self.metadata.os_version}".strip(),
                "panel": self.metadata.panel,
                "web_stack": self.metadata.web_server,
                "database": self.metadata.database,
                "firewall": self.metadata.firewall,
            }
        if getattr(safe_incident, "evidence", ""):
            payload["incident_evidence_logs"] = safe_incident.evidence

        try:
            request = self._build_request(payload)
            with urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                data = json.loads(response.read().decode("utf-8", errors="replace"))
            if not isinstance(data, dict):
                self.logger.warning("%s API returned an invalid response", self.provider.title())
                return ""
            return self._extract_text(data)[:4000]
        except HTTPError as exc:
            err_msg = ""
            try:
                raw_err = exc.read().decode("utf-8", errors="replace")
                parsed_err = json.loads(raw_err)
                if isinstance(parsed_err, dict):
                    if "error" in parsed_err and isinstance(parsed_err["error"], dict):
                        err_msg = parsed_err["error"].get("message", "")
                    elif "error" in parsed_err and isinstance(parsed_err["error"], str):
                        err_msg = parsed_err["error"]
                    elif "message" in parsed_err and isinstance(parsed_err["message"], str):
                        err_msg = parsed_err["message"]
                if not err_msg:
                    err_msg = raw_err[:250]
            except Exception:
                err_msg = ""
            if err_msg:
                self.logger.warning(
                    "%s API returned HTTP %s: %s", self.provider.title(), exc.code, err_msg
                )
            else:
                self.logger.warning("%s API returned HTTP %s", self.provider.title(), exc.code)
        except (
            URLError,
            TimeoutError,
            json.JSONDecodeError,
            OSError,
            UnicodeDecodeError,
            AttributeError,
            TypeError,
        ) as exc:
            self.logger.warning("%s analysis failed: %s", self.provider.title(), exc)
        return ""

    def close(self):
        """Kept for a stable Agent lifecycle; stdlib HTTP requests are per-call."""
