"""Asynchronous Email Dispatch Service with SMTP and Console/Mock fallback."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import smtplib
from email.message import EmailMessage
from typing import Any

from logmorph.config import settings

logger = logging.getLogger(__name__)


def hash_token(raw_token: str) -> str:
    """Generate SHA-256 hash of a raw token for zero-knowledge storage."""
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


class EmailService:
    """Email dispatch service supporting Standard SMTP and development/testing mock modes."""

    def __init__(self) -> None:
        self.sent_emails: list[dict[str, Any]] = []

    def _send_sync_smtp(self, msg: EmailMessage) -> None:
        """Synchronous SMTP socket send intended to run in a background worker thread."""
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
            if settings.SMTP_USE_TLS:
                server.starttls()
            if settings.SMTP_USER and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.send_message(msg)

    async def _send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: str,
    ) -> bool:
        """Dispatch email via SMTP or capture in memory/console during tests/dev."""
        record = {
            "to": to_email,
            "subject": subject,
            "html": html_content,
            "text": text_content,
        }
        self.sent_emails.append(record)

        # In testing environment or if SMTP credentials are not configured, log to console
        if settings.ENVIRONMENT == "test" or not (
            settings.SMTP_USER and settings.SMTP_PASSWORD
        ):
            logger.info(
                "[MOCK EMAIL DISPATCH] To: %s | Subject: %s | Content Preview: %s",
                to_email,
                subject,
                text_content[:150],
            )
            return True

        # Send via live SMTP server in separate thread to prevent blocking asyncio loop
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = settings.EMAIL_FROM
        msg["To"] = to_email
        msg.set_content(text_content)
        msg.add_alternative(html_content, subtype="html")

        try:
            await asyncio.to_thread(self._send_sync_smtp, msg)
            logger.info("Successfully dispatched email to %s via SMTP", to_email)
            return True
        except Exception as e:
            logger.warning(
                "Failed to send email to %s via SMTP (%s). Falling back to log record.",
                to_email,
                e,
            )
            return False

    async def send_verification_email(
        self,
        to_email: str,
        full_name: str,
        raw_token: str,
    ) -> bool:
        """Send email verification link to newly registered user."""
        verification_url = f"{settings.FRONTEND_URL}/verify-email?token={raw_token}"
        subject = "Verify your LogMorph account"

        text_content = (
            f"Hello {full_name},\n\n"
            f"Thank you for signing up for LogMorph. Please verify your email by clicking the link below:\n\n"
            f"{verification_url}\n\n"
            f"This link expires in 24 hours.\n\n"
            f"— The LogMorph Team"
        )

        html_content = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #0f172a; color: #f8fafc; padding: 32px; border-radius: 8px;">
            <h2 style="color: #38bdf8; margin-top: 0;">Welcome to LogMorph</h2>
            <p>Hello <strong>{full_name}</strong>,</p>
            <p>Please confirm that this is your email address to activate your full security analytics privileges.</p>
            <div style="margin: 28px 0;">
                <a href="{verification_url}" style="background: #2563eb; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">Verify Email Address</a>
            </div>
            <p style="color: #94a3b8; font-size: 13px;">If the button does not work, copy and paste this URL into your browser:<br/>
                <a href="{verification_url}" style="color: #38bdf8;">{verification_url}</a>
            </p>
            <p style="color: #64748b; font-size: 12px; margin-top: 32px; border-top: 1px solid #1e293b; padding-top: 16px;">This link will expire in 24 hours. If you did not create a LogMorph account, you can safely ignore this email.</p>
        </div>
        """

        return await self._send_email(to_email, subject, html_content, text_content)

    async def send_password_reset_email(
        self,
        to_email: str,
        full_name: str,
        raw_token: str,
    ) -> bool:
        """Send password reset link to user."""
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={raw_token}"
        subject = "Reset your LogMorph password"

        text_content = (
            f"Hello {full_name},\n\n"
            f"We received a request to reset your LogMorph password. Click the link below to set a new password:\n\n"
            f"{reset_url}\n\n"
            f"This link will expire in 15 minutes.\n\n"
            f"If you did not request this, please ignore this email or contact support.\n\n"
            f"— The LogMorph Security Team"
        )

        html_content = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #0f172a; color: #f8fafc; padding: 32px; border-radius: 8px;">
            <h2 style="color: #f59e0b; margin-top: 0;">Password Reset Request</h2>
            <p>Hello <strong>{full_name}</strong>,</p>
            <p>We received a request to reset your LogMorph password. Click the button below to choose a new password:</p>
            <div style="margin: 28px 0;">
                <a href="{reset_url}" style="background: #d97706; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">Reset Password</a>
            </div>
            <p style="color: #94a3b8; font-size: 13px;">Or copy and paste this URL into your browser:<br/>
                <a href="{reset_url}" style="color: #f59e0b;">{reset_url}</a>
            </p>
            <p style="color: #64748b; font-size: 12px; margin-top: 32px; border-top: 1px solid #1e293b; padding-top: 16px;">This link will expire in 15 minutes. If you did not make this request, your account is still secure and no changes were made.</p>
        </div>
        """

        return await self._send_email(to_email, subject, html_content, text_content)

    async def send_password_changed_notification(
        self,
        to_email: str,
        full_name: str,
    ) -> bool:
        """Send security notice that password was successfully modified."""
        subject = "Security Notice: Your LogMorph password has been changed"

        text_content = (
            f"Hello {full_name},\n\n"
            f"This is an automated notification to confirm that your LogMorph account password was successfully changed.\n\n"
            f"All active sessions on other devices have been terminated.\n\n"
            f"If you did not perform this change, please contact security immediately.\n\n"
            f"— The LogMorph Security Team"
        )

        html_content = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #0f172a; color: #f8fafc; padding: 32px; border-radius: 8px;">
            <h2 style="color: #10b981; margin-top: 0;">Security Alert: Password Updated</h2>
            <p>Hello <strong>{full_name}</strong>,</p>
            <p>Your LogMorph account password was successfully updated. All previous sessions across all devices have been revoked.</p>
            <p style="color: #ef4444; font-weight: bold;">If you did not authorize this change, please contact your administrator or security team immediately.</p>
        </div>
        """

        return await self._send_email(to_email, subject, html_content, text_content)


_email_service = EmailService()


def get_email_service() -> EmailService:
    """Return singleton EmailService instance."""
    return _email_service
