from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value")


def _int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


def _float(name: str, default: float) -> float:
    return float(os.getenv(name, str(default)))


def _csv(name: str, default: str = "") -> List[str]:
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


def _optional_int(name: str) -> Optional[int]:
    value = os.getenv(name, "").strip()
    return int(value) if value else None


@dataclass(frozen=True)
class Config:
    server_name: str = os.getenv("SERVER_NAME", os.uname().nodename)
    environment: str = os.getenv("ENVIRONMENT", "production")

    health_interval: int = _int("HEALTH_INTERVAL", 60)
    log_interval: int = _int("LOG_INTERVAL", 15)
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

    gemini_enabled: bool = _bool("GEMINI_ENABLED", False)
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    gemini_timeout_seconds: int = _int("GEMINI_TIMEOUT_SECONDS", 8)
    gemini_max_output_tokens: int = _int("GEMINI_MAX_OUTPUT_TOKENS", 400)
    gemini_rate_limit_per_minute: int = _int("GEMINI_RATE_LIMIT_PER_MINUTE", 10)

    state_dir: Path = Path(os.getenv("STATE_DIR", "/var/lib/server-ai-agent"))
    log_file: Path = Path(os.getenv("LOG_FILE", "/var/log/server-ai-agent/agent.log"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO").upper()

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
        if self.health_interval < 10 or self.log_interval < 2:
            errors.append("Intervals are too aggressive; HEALTH_INTERVAL>=10 and LOG_INTERVAL>=2")
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
        web_logs = self.resolved_web_error_logs()
        if len(web_logs) > 12:
            errors.append("WEB_ERROR_LOGS supports at most 12 explicit paths")
        if any(not Path(path).is_absolute() for path in web_logs):
            errors.append("WEB_ERROR_LOGS entries must be absolute paths")
        if self.kernel_monitor_enabled:
            kernel_logs = self.resolved_kernel_logs()
            if len(kernel_logs) > 6:
                errors.append("KERNEL_ERROR_LOGS supports at most 6 explicit paths")
            if any(not Path(path).is_absolute() for path in kernel_logs):
                errors.append("KERNEL_ERROR_LOGS entries must be absolute paths")
        if not 1 <= self.smtp_port <= 65535:
            errors.append("SMTP_PORT must be between 1 and 65535")
        if self.smtp_timeout < 1 or self.telegram_timeout < 1 or self.gemini_timeout_seconds < 1:
            errors.append("SMTP_TIMEOUT, TELEGRAM_TIMEOUT, and GEMINI_TIMEOUT_SECONDS must be positive")
        if self.gemini_enabled and not self.gemini_api_key:
            errors.append("GEMINI_API_KEY is required when GEMINI_ENABLED=true")
        if self.gemini_enabled and not re.fullmatch(r"[A-Za-z0-9._-]+", self.gemini_model):
            errors.append("GEMINI_MODEL contains unsupported characters")
        if not 1 <= self.gemini_max_output_tokens <= 2048:
            errors.append("GEMINI_MAX_OUTPUT_TOKENS must be between 1 and 2048")
        if not 1 <= self.gemini_rate_limit_per_minute <= 120:
            errors.append("GEMINI_RATE_LIMIT_PER_MINUTE must be between 1 and 120")
        if errors:
            raise ValueError("; ".join(errors))
