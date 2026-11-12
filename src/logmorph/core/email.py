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

# Hosted public CDN / raw URL for LogMorph official brand favicon from the frontend branch
LOGMORPH_ICON_URL = (
    "https://raw.githubusercontent.com/abhayXdev/LogMorph/frontend-dev/frontend/public/favicon.svg"
)


def hash_token(raw_token: str) -> str:
    """Generate SHA-256 hash of a raw token for zero-knowledge storage."""
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


def _build_professional_email_html(
    *,
    preheader: str,
    headline: str,
    recipient_name: str,
    lead_text: str,
    cta_text: str | None = None,
    cta_url: str | None = None,
    cta_color: str = "#863bff",
    direct_link_label: str | None = None,
    expiry_notice: str | None = None,
    security_footer: str | None = None,
) -> str:
    """Generate a clean, modern, enterprise-grade transactional HTML email.

    Styled after Linear, Stripe, and Vercel: clean white card on subtle canvas,
    brand purple polygon icon from the frontend design system, accessible typography,
    and responsive dark-mode support without AI/robotic buzzwords.
    """
    first_name = recipient_name.strip().split()[0] if recipient_name else "there"

    button_block = ""
    if cta_text and cta_url:
        button_block = f"""
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin: 28px 0; width: 100%;">
            <tr>
                <td align="center">
                    <a href="{cta_url}" target="_blank" style="display: inline-block; background-color: {cta_color}; color: #ffffff; font-size: 14px; font-weight: 600; text-decoration: none; padding: 13px 32px; border-radius: 8px; box-shadow: 0 4px 14px rgba(134, 59, 255, 0.28); letter-spacing: -0.01em;">
                        {cta_text} &rarr;
                    </a>
                </td>
            </tr>
        </table>
        """

    direct_link_block = ""
    if cta_url:
        label = direct_link_label or "If the button above doesn't work, copy and paste this link into your browser:"
        direct_link_block = f"""
        <p style="margin: 0 0 8px 0; font-size: 13px; line-height: 1.5; color: #64748b;">
            {label}
        </p>
        <p style="margin: 0 0 24px 0; font-size: 12px; line-height: 1.5; word-break: break-all;">
            <a href="{cta_url}" style="color: #863bff; text-decoration: underline;">{cta_url}</a>
        </p>
        """

    expiry_block = ""
    if expiry_notice:
        expiry_block = f"""
        <p style="margin: 0 0 16px 0; font-size: 13px; line-height: 1.5; color: #64748b;">
            {expiry_notice}
        </p>
        """

    security_note = security_footer or (
        "If you didn't request this email, you can safely ignore it. Your account remains secure."
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{headline}</title>
    <!--[if mso]>
    <noscript>
        <xml>
            <o:OfficeDocumentSettings>
                <o:PixelsPerInch>96</o:PixelsPerInch>
            </o:OfficeDocumentSettings>
        </xml>
    </noscript>
    <![endif]-->
    <style>
        @media (prefers-color-scheme: dark) {{
            body, .bg-canvas {{ background-color: #070b14 !important; }}
            .email-card {{ background-color: #0f172a !important; border-color: #1e293b !important; }}
            .text-title {{ color: #f8fafc !important; }}
            .text-body {{ color: #cbd5e1 !important; }}
            .text-muted {{ color: #94a3b8 !important; }}
            .text-sub {{ color: #64748b !important; }}
            .card-divider {{ background-color: #1e293b !important; }}
        }}
    </style>
</head>
<body class="bg-canvas" style="margin: 0; padding: 0; background-color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased;">
    <div style="display: none; font-size: 1px; color: #f8fafc; line-height: 1px; max-height: 0px; max-width: 0px; opacity: 0; overflow: hidden;">
        {preheader} &zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;
    </div>

    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" class="bg-canvas" style="background-color: #f8fafc; padding: 48px 16px;">
        <tr>
            <td align="center">
                <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width: 520px;">
                    <!-- Brand Header -->
                    <tr>
                        <td align="center" style="padding-bottom: 28px;">
                            <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                                <tr>
                                    <td valign="middle" style="padding-right: 10px;">
                                        <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                                            <tr>
                                                <td align="center" valign="middle" style="width: 36px; height: 36px; background: linear-gradient(135deg, #863bff 0%, #7e14ff 50%, #47bfff 100%); border-radius: 9px; box-shadow: 0 4px 12px rgba(134, 59, 255, 0.25);">
                                                    <img src="{LOGMORPH_ICON_URL}" width="22" height="22" alt="LogMorph" style="display: block; border: 0;" />
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                    <td valign="middle">
                                        <span class="text-title" style="font-size: 20px; font-weight: 700; letter-spacing: -0.02em; color: #0f172a;">LogMorph</span>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Main White / Dark Card -->
                    <tr>
                        <td>
                            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" class="email-card" style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 40px 36px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -2px rgba(0, 0, 0, 0.05);">
                                <tr>
                                    <td>
                                        <h1 class="text-title" style="margin: 0 0 16px 0; font-size: 20px; font-weight: 700; color: #0f172a; letter-spacing: -0.02em;">
                                            {headline}
                                        </h1>
                                        <p class="text-body" style="margin: 0 0 14px 0; font-size: 15px; line-height: 1.6; color: #334155;">
                                            Hi {first_name},
                                        </p>
                                        <p class="text-body" style="margin: 0 0 20px 0; font-size: 15px; line-height: 1.6; color: #334155;">
                                            {lead_text}
                                        </p>
                                        {button_block}
                                        {expiry_block}
                                        {direct_link_block}

                                        <!-- Card Divider -->
                                        <div class="card-divider" style="height: 1px; background-color: #f1f5f9; width: 100%; margin: 24px 0 20px 0;"></div>

                                        <p class="text-sub" style="margin: 0; font-size: 12px; line-height: 1.5; color: #94a3b8;">
                                            {security_note}
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Subtle Footer -->
                    <tr>
                        <td align="center" style="padding-top: 24px;">
                            <p style="margin: 0 0 4px 0; font-size: 12px; color: #94a3b8;">
                                LogMorph, Inc. &bull; Real-Time Log Pipeline & Security Analytics
                            </p>
                            <p style="margin: 0; font-size: 11px; color: #cbd5e1;">
                                &copy; 2026 LogMorph, Inc. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""


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

        html_content = _build_professional_email_html(
            preheader="Verify your email address to get started with LogMorph.",
            headline="Verify your email address",
            recipient_name=full_name,
            lead_text="Thanks for signing up for LogMorph. Please confirm your email address by clicking the button below to activate your account and access your dashboard:",
            cta_text="Verify email address",
            cta_url=verification_url,
            cta_color="#863bff",
            expiry_notice="This link will expire in 24 hours.",
            security_footer="If you didn't create an account with LogMorph, you can safely ignore this email.",
        )

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

        html_content = _build_professional_email_html(
            preheader="Reset your LogMorph account password.",
            headline="Reset your password",
            recipient_name=full_name,
            lead_text="We received a request to reset the password for your LogMorph account. Click the button below to choose a new password:",
            cta_text="Reset password",
            cta_url=reset_url,
            cta_color="#863bff",
            expiry_notice="This single-use link will expire in 15 minutes.",
            security_footer="If you didn't request a password reset, you can safely ignore this email. Your account remains secure.",
        )

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

        html_content = _build_professional_email_html(
            preheader="Your LogMorph account password was changed.",
            headline="Your password was changed",
            recipient_name=full_name,
            lead_text="This is an automated confirmation that the password for your LogMorph account was recently updated. All prior active sessions across devices have been revoked.",
            security_footer="If you didn't make this change, please contact your security administrator immediately.",
        )

        return await self._send_email(to_email, subject, html_content, text_content)


_email_service = EmailService()


def get_email_service() -> EmailService:
    """Return singleton EmailService instance."""
    return _email_service
