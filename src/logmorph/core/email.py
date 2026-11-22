"""Asynchronous Email Dispatch Service with SMTP and Console/Mock fallback."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import smtplib
from email.message import EmailMessage
from typing import Any

import httpx

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
    cta_color: str = "#590907",
    direct_link_label: str | None = None,
    expiry_notice: str | None = None,
    security_footer: str | None = None,
) -> str:
    """Generate a clean, modern, enterprise-grade transactional HTML email.

    Branded with LogMorph's refined visual palette:
    - Deep Burgundy: #590907 (brand header, primary CTA, headlines)
    - Warm Cream Beige: #E8D2B5 (card borders, dividers, subtle accents)
    - Muted Sage Grey: #A5A79B (metadata, security notes, subtext)
    """
    first_name = recipient_name.strip().split()[0] if recipient_name else "there"

    button_block = ""
    if cta_text and cta_url:
        button_block = f"""
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin: 28px 0; width: 100%;">
            <tr>
                <td align="center">
                    <a href="{cta_url}" target="_blank" style="display: inline-block; background-color: {cta_color}; color: #ffffff; font-size: 14px; font-weight: 600; text-decoration: none; padding: 13px 32px; border-radius: 8px; box-shadow: 0 4px 14px rgba(89, 9, 7, 0.28); letter-spacing: -0.01em;">
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
        <p style="margin: 0 0 8px 0; font-size: 13px; line-height: 1.5; color: #78716c;">
            {label}
        </p>
        <p style="margin: 0 0 24px 0; font-size: 12px; line-height: 1.5; word-break: break-all;">
            <a href="{cta_url}" style="color: #590907; text-decoration: underline; font-weight: 500;">{cta_url}</a>
        </p>
        """

    expiry_block = ""
    if expiry_notice:
        expiry_block = f"""
        <div style="background-color: #FAF6F0; border-left: 3px solid #590907; border-top: 1px solid #E8D2B5; border-right: 1px solid #E8D2B5; border-bottom: 1px solid #E8D2B5; border-radius: 6px; padding: 12px 16px; margin: 20px 0;">
            <p style="margin: 0; font-size: 13px; line-height: 1.5; color: #590907; font-weight: 500;">
                {expiry_notice}
            </p>
        </div>
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
            body, .bg-canvas {{ background-color: #161311 !important; }}
            .email-card {{ background-color: #201B19 !important; border-color: #3D302C !important; }}
            .text-title {{ color: #F5EBE1 !important; }}
            .text-body {{ color: #D6CCC2 !important; }}
            .text-muted {{ color: #A5A79B !important; }}
            .text-sub {{ color: #8F8C81 !important; }}
            .card-divider {{ background-color: #3D302C !important; }}
        }}
    </style>
</head>
<body class="bg-canvas" style="margin: 0; padding: 0; background-color: #FAF6F0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased;">
    <div style="display: none; font-size: 1px; color: #FAF6F0; line-height: 1px; max-height: 0px; max-width: 0px; opacity: 0; overflow: hidden;">
        {preheader} &zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;
    </div>

    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" class="bg-canvas" style="background-color: #FAF6F0; padding: 48px 16px;">
        <tr>
            <td align="center">
                <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width: 520px;">
                    <!-- Brand Header -->
                    <tr>
                        <td align="center" style="padding-bottom: 28px;">
                            <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                                <tr>
                                    <td valign="middle" style="padding-right: 12px;">
                                        <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                                            <tr>
                                                <td align="center" valign="middle" style="width: 38px; height: 38px; background-color: #590907; border-radius: 10px; box-shadow: 0 4px 12px rgba(89, 9, 7, 0.28);">
                                                    <svg width="22" height="22" viewBox="0 0 22 22" fill="none" xmlns="http://www.w3.org/2000/svg" style="display: block;">
                                                        <path d="M2.84 4.58H7.24C7.8 4.58 8.25 5.04 8.25 5.59C8.25 6.15 7.8 6.6 7.24 6.6H2.84C2.29 6.6 1.83 6.15 1.83 5.59C1.83 5.04 2.29 4.58 2.84 4.58Z" fill="#E8D2B5"/>
                                                        <path d="M2.84 9.99H5.41C5.97 9.99 6.42 10.44 6.42 11C6.42 11.56 5.96 12.01 5.41 12.01H2.84C2.29 12.01 1.83 11.56 1.83 11C1.83 10.44 2.29 9.99 2.84 9.99Z" fill="#A5A79B"/>
                                                        <path d="M2.84 15.4H8.16C8.71 15.4 9.17 15.85 9.17 16.41C9.17 16.96 8.71 17.42 8.16 17.42H2.84C2.29 17.42 1.83 16.96 1.83 16.41C1.83 15.85 2.29 15.4 2.84 15.4Z" fill="#E8D2B5"/>
                                                        <path d="M9.625 7.79L12.375 11L9.625 14.21" stroke-width="1.83" stroke-linecap="round" stroke-linejoin="round" stroke="#ffffff"/>
                                                        <path d="M15.22 4.58H19.16C19.71 4.58 20.17 5.04 20.17 5.59C20.17 6.15 19.71 6.6 19.16 6.6H15.22C14.66 6.6 14.21 6.15 14.21 5.59C14.21 5.04 14.66 4.58 15.22 4.58Z" fill="#ffffff"/>
                                                        <path d="M15.22 9.99H19.16C19.71 9.99 20.17 10.44 20.17 11C20.17 11.56 19.71 12.01 19.16 12.01H15.22C14.66 12.01 14.21 11.56 14.21 11C14.21 10.44 14.66 9.99 15.22 9.99Z" fill="#E8D2B5"/>
                                                        <path d="M15.22 15.4H19.16C19.71 15.4 20.17 15.85 20.17 16.41C20.17 16.96 19.71 17.42 19.16 17.42H15.22C14.66 17.42 14.21 16.96 14.21 16.41C14.21 15.85 14.66 15.4 15.22 15.4Z" fill="#ffffff"/>
                                                    </svg>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                    <td valign="middle">
                                        <span class="text-title" style="font-size: 20px; font-weight: 700; letter-spacing: -0.02em; color: #590907;">LogMorph</span>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Main Card -->
                    <tr>
                        <td>
                            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" class="email-card" style="background-color: #ffffff; border: 1px solid #E8D2B5; border-radius: 12px; padding: 40px 36px; box-shadow: 0 4px 16px rgba(89, 9, 7, 0.05);">
                                <tr>
                                    <td>
                                        <h1 class="text-title" style="margin: 0 0 16px 0; font-size: 20px; font-weight: 700; color: #590907; letter-spacing: -0.02em;">
                                            {headline}
                                        </h1>
                                        <p class="text-body" style="margin: 0 0 14px 0; font-size: 15px; line-height: 1.6; color: #2D2321;">
                                            Hi {first_name},
                                        </p>
                                        <p class="text-body" style="margin: 0 0 20px 0; font-size: 15px; line-height: 1.6; color: #2D2321;">
                                            {lead_text}
                                        </p>
                                        {button_block}
                                        {expiry_block}
                                        {direct_link_block}

                                        <!-- Card Divider -->
                                        <div class="card-divider" style="height: 1px; background-color: #E8D2B5; width: 100%; margin: 24px 0 20px 0;"></div>

                                        <p class="text-sub" style="margin: 0; font-size: 12px; line-height: 1.5; color: #A5A79B;">
                                            {security_note}
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td align="center" style="padding-top: 24px;">
                            <p style="margin: 0 0 4px 0; font-size: 12px; color: #A5A79B;">
                                LogMorph, Inc. &bull; Real-Time Log Pipeline & Security Analytics
                            </p>
                            <p style="margin: 0; font-size: 11px; color: #C4BEB5;">
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

    async def _send_via_brevo_api(
        self,
        api_key: str,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: str,
    ) -> bool:
        """Dispatch email via Brevo transactional HTTP REST API over HTTPS port 443."""
        url = "https://api.brevo.com/v3/smtp/email"
        headers = {
            "api-key": api_key,
            "accept": "application/json",
            "content-type": "application/json",
        }
        payload = {
            "sender": {"email": settings.EMAIL_FROM, "name": "LogMorph"},
            "to": [{"email": to_email}],
            "subject": subject,
            "htmlContent": html_content,
            "textContent": text_content,
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, headers=headers, json=payload)
                if resp.status_code in (200, 201, 202):
                    logger.info("Successfully dispatched email to %s via Brevo HTTP REST API (port 443)", to_email)
                    return True
                logger.warning(
                    "Brevo HTTP API returned status %d for %s: %s",
                    resp.status_code,
                    to_email,
                    resp.text[:200],
                )
                return False
        except Exception as e:
            logger.warning("Brevo HTTP API dispatch encountered error for %s: %s", to_email, e)
            return False

    async def _send_via_resend_api(
        self,
        api_key: str,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: str,
    ) -> bool:
        """Dispatch email via Resend HTTP REST API over HTTPS port 443."""
        url = "https://api.resend.com/emails"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "from": settings.EMAIL_FROM,
            "to": [to_email],
            "subject": subject,
            "html": html_content,
            "text": text_content,
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, headers=headers, json=payload)
                if resp.status_code in (200, 201, 202):
                    logger.info("Successfully dispatched email to %s via Resend HTTP REST API (port 443)", to_email)
                    return True
                logger.warning(
                    "Resend HTTP API returned status %d for %s: %s",
                    resp.status_code,
                    to_email,
                    resp.text[:200],
                )
                return False
        except Exception as e:
            logger.warning("Resend HTTP API dispatch encountered error for %s: %s", to_email, e)
            return False

    def _send_sync_smtp(self, msg: EmailMessage) -> None:
        """Synchronous SMTP socket send intended to run in a background worker thread."""
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
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
        """Dispatch email via HTTPS REST API (Brevo/Resend) or SMTP, with console logging."""
        record = {
            "to": to_email,
            "subject": subject,
            "html": html_content,
            "text": text_content,
        }
        self.sent_emails.append(record)

        # 1. In testing environment or if no credentials configured, log to console
        brevo_key = settings.BREVO_API_KEY or (
            settings.SMTP_PASSWORD
            if (settings.SMTP_PASSWORD and settings.SMTP_PASSWORD.startswith("xkeysib-"))
            else None
        )
        has_credentials = bool(
            brevo_key
            or settings.RESEND_API_KEY
            or (settings.SMTP_USER and settings.SMTP_PASSWORD)
        )

        if settings.ENVIRONMENT == "test" or not has_credentials:
            logger.info(
                "[MOCK EMAIL DISPATCH] To: %s | Subject: %s | Content Preview: %s",
                to_email,
                subject,
                text_content[:150],
            )
            return True

        # 2. Priority 1: Brevo HTTP REST API (HTTPS port 443 — works everywhere on Render/cloud)
        if brevo_key and await self._send_via_brevo_api(
            brevo_key, to_email, subject, html_content, text_content
        ):
            return True

        # 3. Priority 2: Resend HTTP REST API (HTTPS port 443)
        if settings.RESEND_API_KEY and await self._send_via_resend_api(
            settings.RESEND_API_KEY, to_email, subject, html_content, text_content
        ):
            return True

        # 4. Priority 3: Standard SMTP (for environments where outbound ports 587/465 are permitted)
        if settings.SMTP_USER and settings.SMTP_PASSWORD:
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
                    "Failed to send email to %s via SMTP (%s). "
                    "Note: Render Free Tier blocks outbound ports 25, 465, and 587. "
                    "Use BREVO_API_KEY or RESEND_API_KEY to send over HTTPS port 443.",
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
            cta_color="#590907",
            expiry_notice="This link will expire in 24 hours.",
            security_footer="If you didn't create an account with LogMorph, you can safely ignore this email.",
        )

        sent = await self._send_email(to_email, subject, html_content, text_content)
        logger.info(
            "[ACCOUNT VERIFICATION LINK] Recipient: %s | URL: %s (delivered: %s)",
            to_email,
            verification_url,
            sent,
        )
        return sent

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
            cta_color="#590907",
            expiry_notice="This single-use link will expire in 15 minutes.",
            security_footer="If you didn't request a password reset, you can safely ignore this email. Your account remains secure.",
        )

        sent = await self._send_email(to_email, subject, html_content, text_content)
        logger.info(
            "[PASSWORD RESET LINK] Recipient: %s | URL: %s (delivered: %s)",
            to_email,
            reset_url,
            sent,
        )
        return sent

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
