from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv

from ..detectors.service_profiles import PROFILE_NAMES

load_dotenv()

_SERVICE_UNIT_RE = re.compile(r"^[a-zA-Z0-9_@.:-]+$")


def _env_str(name: str, default: str = "") -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    cleaned = raw.strip().strip("'\"").strip()
    return cleaned if cleaned else default


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    cleaned = raw.strip().strip("'\"").strip().lower()
    if not cleaned:
        return default
    if cleaned in {"1", "true", "yes", "on"}:
        return True
    if cleaned in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value")


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    cleaned = raw.strip().strip("'\"").strip()
    if not cleaned:
        return default
    return int(cleaned)


def _float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    cleaned = raw.strip().strip("'\"").strip()
    if not cleaned:
        return default
    return float(cleaned)


def _csv(name: str, default: str = "") -> List[str]:
    raw = os.getenv(name)
    val = raw.strip().strip("'\"") if raw is not None else default
    return [x.strip() for x in val.split(",") if x.strip()]


def _optional_int(name: str) -> Optional[int]:
    raw = os.getenv(name)
    if raw is None:
        return None
    cleaned = raw.strip().strip("'\"").strip()
    return int(cleaned) if cleaned else None


def _default_server_name() -> str:
    import socket
    name = os.getenv("SERVER_NAME")
    if name:
        return name
    try:
        return os.uname().nodename
    except AttributeError:
        return socket.gethostname()


@dataclass(frozen=True)
class Config:
    server_name: str = field(default_factory=_default_server_name)
    environment: str = os.getenv("ENVIRONMENT", "production")

    auto_detect_environment: bool = _bool("AUTO_DETECT_ENVIRONMENT", True)
    auto_detect_services: bool = _bool("AUTO_DETECT_SERVICES", True)
    collect_incident_evidence: bool = _bool("COLLECT_INCIDENT_EVIDENCE", True)
    evidence_lines: int = _int("EVIDENCE_LINES", 15)

    health_interval: int = _int("HEALTH_INTERVAL", 60)
    log_interval: int = _int("LOG_INTERVAL", 15)
    heartbeat_stale_seconds: int = _int("HEARTBEAT_STALE_SECONDS", 300)
    max_log_lines_per_cycle: int = _int("MAX_LOG_LINES_PER_CYCLE", 250)
    max_log_line_chars: int = _int("MAX_LOG_LINE_CHARS", 4096)

    cpu_warning: float = _float("CPU_WARNING", 85)
    cpu_critical: float = _float("CPU_CRITICAL", 95)
    memory_warning: float = _float("MEMORY_WARNING", 85)
    memory_critical: float = _float("MEMORY_CRITICAL", 95)
    disk_warning: float = _float("DISK_WARNING", 85)
    disk_critical: float = _float("DISK_CRITICAL", 95)
    load_warning_per_cpu: float = _float("LOAD_WARNING_PER_CPU", 1.50)
    load_critical_per_cpu: float = _float("LOAD_CRITICAL_PER_CPU", 2.50)

    disk_paths: List[str] = field(
        default_factory=lambda: os.getenv("DISK_PATHS", "/").split()
    )
    services: List[str] = field(
        default_factory=lambda: _csv("SERVICES", "nginx,apache2,httpd,ssh,sshd")
    )
    alert_on_missing_service: bool = _bool("ALERT_ON_MISSING_SERVICE", False)
    service_profile: str = os.getenv("SERVICE_PROFILE", "auto").strip().lower()
    services_required: List[str] = field(default_factory=lambda: _csv("SERVICES_REQUIRED"))
    services_optional: List[str] = field(default_factory=lambda: _csv("SERVICES_OPTIONAL"))
    service_failure_threshold: int = _int("SERVICE_FAILURE_THRESHOLD", 2)

    nginx_error_log: str = os.getenv("NGINX_ERROR_LOG", "/var/log/nginx/error.log")
    apache_error_log: str = os.getenv("APACHE_ERROR_LOG", "/var/log/apache2/error.log")
    apache_rhel_error_log: str = os.getenv("APACHE_RHEL_ERROR_LOG", "/var/log/httpd/error_log")
    web_error_logs: List[str] = field(default_factory=lambda: _csv("WEB_ERROR_LOGS"))
    web_error_batch_threshold: int = _int("WEB_ERROR_BATCH_THRESHOLD", 1)
    max_log_sample_chars: int = _int("MAX_LOG_SAMPLE_CHARS", 600)

    auth_log: str = os.getenv("AUTH_LOG", "/var/log/auth.log")
    auth_log_rhel: str = os.getenv("AUTH_LOG_RHEL", "/var/log/secure")
    ssh_failed_threshold: int = _int("SSH_FAILED_THRESHOLD", 5)
    ssh_failed_window_seconds: int = _int("SSH_FAILED_WINDOW_SECONDS", 300)
    ssh_failure_tracked_ips_max: int = _int("SSH_FAILURE_TRACKED_IPS_MAX", 1000)
    ssh_alert_success: bool = _bool("SSH_ALERT_SUCCESS", True)
    ssh_alert_failed_burst: bool = _bool("SSH_ALERT_FAILED_BURST", True)
    ssh_alert_root_login: bool = _bool("SSH_ALERT_ROOT_LOGIN", True)
    trusted_ssh_networks: List[str] = field(default_factory=lambda: _csv("TRUSTED_SSH_NETWORKS"))

    kernel_monitor_enabled: bool = _bool("KERNEL_MONITOR_ENABLED", True)
    kernel_log: str = os.getenv("KERNEL_LOG", "/var/log/kern.log")
    kernel_log_rhel: str = os.getenv("KERNEL_LOG_RHEL", "/var/log/messages")
    kernel_error_logs: List[str] = field(default_factory=lambda: _csv("KERNEL_ERROR_LOGS"))
    kernel_journal_fallback: bool = _bool("KERNEL_JOURNAL_FALLBACK", True)

    alert_cooldown_seconds: int = _int("ALERT_COOLDOWN_SECONDS", 900)
    recovery_alerts: bool = _bool("RECOVERY_ALERTS", True)
    alert_channel: str = os.getenv("ALERT_CHANNEL", "email").strip().lower()

    smtp_host: str = os.getenv("SMTP_HOST", "")
    smtp_port: int = _int("SMTP_PORT", 587)
    smtp_security: str = os.getenv("SMTP_SECURITY", "starttls").lower()
    smtp_username: str = os.getenv("SMTP_USERNAME", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    smtp_from: str = os.getenv("SMTP_FROM", "")
    smtp_to: List[str] = field(default_factory=lambda: _csv("SMTP_TO"))
    smtp_timeout: int = _int("SMTP_TIMEOUT", 20)

    telegram_bot_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    telegram_chat_id: str = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    telegram_message_thread_id: Optional[int] = _optional_int("TELEGRAM_MESSAGE_THREAD_ID")
    telegram_timeout: int = _int("TELEGRAM_TIMEOUT", 10)

    escalation_channel: str = os.getenv("ESCALATION_CHANNEL", "none").strip().lower()
    escalation_telegram_bot_token: str = os.getenv(
        "ESCALATION_TELEGRAM_BOT_TOKEN", ""
    ).strip()
    escalation_telegram_chat_id: str = os.getenv(
        "ESCALATION_TELEGRAM_CHAT_ID", ""
    ).strip()
    escalation_telegram_message_thread_id: Optional[int] = _optional_int(
        "ESCALATION_TELEGRAM_MESSAGE_THREAD_ID"
    )
    escalation_min_severity: str = os.getenv(
        "ESCALATION_MIN_SEVERITY", "CRITICAL"
    ).strip().upper()

    ai_enabled: bool = _bool("AI_ENABLED", _bool("GEMINI_ENABLED", False))
    ai_provider: str = (
        _env_str("AI_PROVIDER") or ("gemini" if _env_str("GEMINI_API_KEY") else "deepseek")
    ).lower()
    ai_api_key: str = _env_str("AI_API_KEY") or _env_str("GEMINI_API_KEY")
    ai_model: str = _env_str("AI_MODEL") or _env_str("GEMINI_MODEL")
    ai_base_url: str = _env_str("AI_BASE_URL")
    ai_timeout_seconds: int = _int("AI_TIMEOUT_SECONDS", _int("GEMINI_TIMEOUT_SECONDS", 10))
    ai_max_output_tokens: int = _int("AI_MAX_OUTPUT_TOKENS", _int("GEMINI_MAX_OUTPUT_TOKENS", 400))
    ai_rate_limit_per_minute: int = _int("AI_RATE_LIMIT_PER_MINUTE", _int("GEMINI_RATE_LIMIT_PER_MINUTE", 10))

    state_dir: Path = Path(os.getenv("STATE_DIR", "/var/lib/server-ai-agent"))
    log_file: Path = Path(os.getenv("LOG_FILE", "/var/log/server-ai-agent/agent.log"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO").upper()
    log_format: str = os.getenv("LOG_FORMAT", "text").strip().lower()

    def resolved_ai_model(self) -> str:
        if self.ai_model:
            return self.ai_model
        defaults = {
            "deepseek": "deepseek-chat",
            "openai": "gpt-4o-mini",
            "kimi": "moonshot-v1-8k",
            "moonshot": "moonshot-v1-8k",
            "groq": "llama-3.3-70b-versatile",
            "openrouter": "deepseek/deepseek-chat",
            "claude": "claude-3-5-haiku-20241022",
            "anthropic": "claude-3-5-haiku-20241022",
            "gemini": "gemini-1.5-flash",
        }
        return defaults.get(self.ai_provider, "deepseek-chat")

    def resolved_ai_base_url(self) -> str:
        if self.ai_base_url:
            return self.ai_base_url.rstrip("/")
        defaults = {
            "deepseek": "https://api.deepseek.com/v1",
            "openai": "https://api.openai.com/v1",
            "kimi": "https://api.moonshot.cn/v1",
            "moonshot": "https://api.moonshot.cn/v1",
            "groq": "https://api.groq.com/openai/v1",
            "openrouter": "https://openrouter.ai/api/v1",
            "claude": "https://api.anthropic.com/v1",
            "anthropic": "https://api.anthropic.com/v1",
            "gemini": "https://generativelanguage.googleapis.com/v1beta/models",
        }
        return defaults.get(self.ai_provider, "https://api.deepseek.com/v1")

    # Backward compatibility properties for Gemini
    @property
    def gemini_enabled(self) -> bool:
        return self.ai_enabled

    @property
    def gemini_api_key(self) -> str:
        return self.ai_api_key

    @property
    def gemini_model(self) -> str:
        return self.resolved_ai_model()

    @property
    def gemini_timeout_seconds(self) -> int:
        return self.ai_timeout_seconds

    @property
    def gemini_max_output_tokens(self) -> int:
        return self.ai_max_output_tokens

    @property
    def gemini_rate_limit_per_minute(self) -> int:
        return self.ai_rate_limit_per_minute

    def resolved_web_error_logs(self) -> List[str]:
        """Return explicit log paths without discovering arbitrary vhost files."""
        paths = self.web_error_logs or [
            self.nginx_error_log,
            self.apache_error_log,
            self.apache_rhel_error_log,
        ]
        return list(dict.fromkeys(path for path in paths if path))

    def resolved_kernel_logs(self) -> List[str]:
        """Return explicit kernel/system log paths."""
        paths = self.kernel_error_logs or [
            self.kernel_log,
            self.kernel_log_rhel,
        ]
        return list(dict.fromkeys(path for path in paths if path))

    def validate(self) -> None:
        errors = []
        if self.alert_channel not in {"email", "telegram"}:
            errors.append("ALERT_CHANNEL must be email or telegram")
        if self.alert_channel == "email":
            if not self.smtp_host:
                errors.append("SMTP_HOST is required when ALERT_CHANNEL=email")
            if not self.smtp_from:
                errors.append("SMTP_FROM is required when ALERT_CHANNEL=email")
            if not self.smtp_to:
                errors.append("SMTP_TO must contain at least one recipient when ALERT_CHANNEL=email")
            if self.smtp_security not in {"starttls", "ssl"}:
                errors.append("SMTP_SECURITY must be starttls or ssl")
        if self.alert_channel == "telegram":
            if not self.telegram_bot_token:
                errors.append("TELEGRAM_BOT_TOKEN is required when ALERT_CHANNEL=telegram")
            if not self.telegram_chat_id:
                errors.append("TELEGRAM_CHAT_ID is required when ALERT_CHANNEL=telegram")
            if self.telegram_message_thread_id is not None and self.telegram_message_thread_id < 1:
                errors.append("TELEGRAM_MESSAGE_THREAD_ID must be a positive integer when set")
        if self.escalation_channel not in {"none", "telegram"}:
            errors.append("ESCALATION_CHANNEL must be none or telegram")
        if self.escalation_channel == "telegram":
            if not (self.escalation_telegram_bot_token or self.telegram_bot_token):
                errors.append(
                    "ESCALATION_TELEGRAM_BOT_TOKEN (or TELEGRAM_BOT_TOKEN) is required "
                    "when ESCALATION_CHANNEL=telegram"
                )
            if not self.escalation_telegram_chat_id:
                errors.append(
                    "ESCALATION_TELEGRAM_CHAT_ID is required when ESCALATION_CHANNEL=telegram"
                )
            if (
                self.escalation_telegram_message_thread_id is not None
                and self.escalation_telegram_message_thread_id < 1
            ):
                errors.append(
                    "ESCALATION_TELEGRAM_MESSAGE_THREAD_ID must be a positive integer when set"
                )
        if self.escalation_min_severity not in {"WARNING", "CRITICAL"}:
            errors.append("ESCALATION_MIN_SEVERITY must be WARNING or CRITICAL")
        if self.health_interval < 10 or self.log_interval < 2:
            errors.append("Intervals are too aggressive; HEALTH_INTERVAL>=10 and LOG_INTERVAL>=2")
        if self.heartbeat_stale_seconds < 60:
            errors.append("HEARTBEAT_STALE_SECONDS must be at least 60")
        if self.log_format not in {"text", "json"}:
            errors.append("LOG_FORMAT must be 'text' or 'json'")
        for name, warning, critical in (
            ("CPU", self.cpu_warning, self.cpu_critical),
            ("MEMORY", self.memory_warning, self.memory_critical),
            ("DISK", self.disk_warning, self.disk_critical),
        ):
            if not 0 <= warning <= critical <= 100:
                errors.append(f"{name} thresholds must satisfy 0 <= warning <= critical <= 100")
        if not 0 <= self.load_warning_per_cpu <= self.load_critical_per_cpu:
            errors.append("Load thresholds must satisfy 0 <= warning <= critical")
        if self.max_log_lines_per_cycle < 1 or self.max_log_lines_per_cycle > 10000:
            errors.append("MAX_LOG_LINES_PER_CYCLE must be between 1 and 10000")
        if not 256 <= self.max_log_line_chars <= 65536:
            errors.append("MAX_LOG_LINE_CHARS must be between 256 and 65536")
        if not 100 <= self.max_log_sample_chars <= 4096:
            errors.append("MAX_LOG_SAMPLE_CHARS must be between 100 and 4096")
        if not 1 <= self.ssh_failure_tracked_ips_max <= 100000:
            errors.append("SSH_FAILURE_TRACKED_IPS_MAX must be between 1 and 100000")
        if self.service_profile not in PROFILE_NAMES:
            errors.append(
                "SERVICE_PROFILE must be one of: " + ", ".join(sorted(PROFILE_NAMES))
            )
        if not 1 <= self.service_failure_threshold <= 10:
            errors.append("SERVICE_FAILURE_THRESHOLD must be between 1 and 10")
        required_names = {name.strip() for name in self.services_required if name.strip()}
        optional_names = {name.strip() for name in self.services_optional if name.strip()}
        overlap = sorted(required_names & optional_names)
        if overlap:
            errors.append(
                "Services cannot be both required and optional: " + ", ".join(overlap)
            )
        for label, values in (
            ("SERVICES", self.services),
            ("SERVICES_REQUIRED", self.services_required),
            ("SERVICES_OPTIONAL", self.services_optional),
        ):
            for value in values:
                name = value.strip()
                if name and not _SERVICE_UNIT_RE.match(name):
                    errors.append(f"{label} contains an invalid systemd unit name: {value}")
        web_logs = self.resolved_web_error_logs()
        if len(web_logs) > 12:
            errors.append("WEB_ERROR_LOGS supports at most 12 explicit paths")
        if any(not path.startswith("/") for path in web_logs):
            errors.append("WEB_ERROR_LOGS entries must be absolute paths")
        if self.kernel_monitor_enabled:
            kernel_logs = self.resolved_kernel_logs()
            if len(kernel_logs) > 6:
                errors.append("KERNEL_ERROR_LOGS supports at most 6 explicit paths")
            if any(not path.startswith("/") for path in kernel_logs):
                errors.append("KERNEL_ERROR_LOGS entries must be absolute paths")
        if not 1 <= self.smtp_port <= 65535:
            errors.append("SMTP_PORT must be between 1 and 65535")
        if self.smtp_timeout < 1 or self.telegram_timeout < 1 or self.ai_timeout_seconds < 1:
            errors.append("SMTP_TIMEOUT, TELEGRAM_TIMEOUT, and AI_TIMEOUT_SECONDS must be positive")
        allowed_providers = {
            "gemini", "openai", "deepseek", "kimi", "moonshot",
            "claude", "anthropic", "groq", "openrouter", "custom", "openai_compatible"
        }
        if self.ai_enabled:
            if self.ai_provider not in allowed_providers and not self.ai_base_url:
                errors.append(f"AI_PROVIDER must be one of: {', '.join(sorted(allowed_providers))} (or provide AI_BASE_URL for custom providers)")
            if not self.ai_api_key:
                errors.append("AI_API_KEY is required when AI_ENABLED=true")
            if not 1 <= self.ai_max_output_tokens <= 8192:
                errors.append("AI_MAX_OUTPUT_TOKENS must be between 1 and 8192")
            if not 1 <= self.ai_rate_limit_per_minute <= 120:
                errors.append("AI_RATE_LIMIT_PER_MINUTE must be between 1 and 120")
            if (self.ai_provider in {"custom", "openai_compatible"} or self.ai_provider not in allowed_providers) and not self.ai_base_url:
                errors.append("AI_BASE_URL is required when AI_PROVIDER=custom or using a custom endpoint")
        if errors:
            raise ValueError("; ".join(errors))
