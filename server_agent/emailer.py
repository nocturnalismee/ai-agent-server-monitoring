from __future__ import annotations

import html
import smtplib
import ssl
from email.message import EmailMessage


class EmailNotifier:
    def __init__(self, config, logger):
        self.cfg = config
        self.logger = logger

    def _connect(self):
        context = ssl.create_default_context()
        if self.cfg.smtp_security == "ssl":
            return smtplib.SMTP_SSL(
                self.cfg.smtp_host,
                self.cfg.smtp_port,
                timeout=self.cfg.smtp_timeout,
                context=context,
            )

        smtp = smtplib.SMTP(
            self.cfg.smtp_host,
            self.cfg.smtp_port,
            timeout=self.cfg.smtp_timeout,
        )
        smtp.ehlo()
        if self.cfg.smtp_security == "starttls":
            smtp.starttls(context=context)
            smtp.ehlo()
        return smtp

    def send(self, incident) -> bool:
        msg = EmailMessage()
        msg["From"] = self.cfg.smtp_from
        msg["To"] = ", ".join(self.cfg.smtp_to)
        msg["Subject"] = (
            f"[{incident.severity}] {self.cfg.server_name} - {incident.title}"
        )

        details = "\n".join(f"{k}: {v}" for k, v in incident.details.items())
        text = f"""\
Server: {self.cfg.server_name}
Environment: {self.cfg.environment}
Severity: {incident.severity}
Time (UTC): {incident.timestamp}

{incident.summary}

Details:
{details}
"""
        if incident.ai_analysis:
            text += f"\nAI analysis:\n{incident.ai_analysis}\n"

        msg.set_content(text)

        escaped_details = "<br>".join(
            f"<b>{html.escape(str(k))}</b>: {html.escape(str(v))}"
            for k, v in incident.details.items()
        )
        ai_html = (
            "<h3>AI analysis</h3><pre style='white-space:pre-wrap'>"
            + html.escape(incident.ai_analysis)
            + "</pre>"
            if incident.ai_analysis else ""
        )
        msg.add_alternative(
            f"""\
<html><body>
<h2>{html.escape(incident.severity)} — {html.escape(incident.title)}</h2>
<p><b>Server:</b> {html.escape(self.cfg.server_name)}<br>
<b>Environment:</b> {html.escape(self.cfg.environment)}<br>
<b>Time (UTC):</b> {html.escape(incident.timestamp)}</p>
<p>{html.escape(incident.summary)}</p>
<h3>Details</h3><p>{escaped_details}</p>
{ai_html}
</body></html>
""",
            subtype="html",
        )

        try:
            with self._connect() as smtp:
                if self.cfg.smtp_username:
                    smtp.login(self.cfg.smtp_username, self.cfg.smtp_password)
                smtp.send_message(msg)
            self.logger.info("Alert email sent: %s", msg["Subject"])
            return True
        except Exception as exc:
            self.logger.exception("Failed sending alert email: %s", exc)
            return False

    def send_test(self) -> bool:
        from .models import Incident
        return self.send(Incident(
            kind="test",
            severity="INFO",
            title="Server AI Agent test",
            summary="SMTP configuration is working.",
            fingerprint="test",
            details={"status": "ok"},
        ))
