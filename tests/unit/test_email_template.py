"""Unit tests for the LogMorph transactional email template and branding palette."""

import pytest

from logmorph.core.email import (
    _build_professional_email_html,
    get_email_service,
)


def test_build_professional_email_html_contains_palette():
    """Verify that generated email HTML contains the exact brand palette colors."""
    html = _build_professional_email_html(
        preheader="Test email preheader",
        headline="Action Required",
        recipient_name="Alice Smith",
        lead_text="Please click the button below to verify your account.",
        cta_text="Confirm Now",
        cta_url="https://logmorph.onrender.com/verify?token=xyz123",
        expiry_notice="This link expires in 24 hours.",
    )

    # 1. Deep Burgundy #590907
    assert "#590907" in html
    # 2. Warm Cream Beige #E8D2B5
    assert "#E8D2B5" in html
    # 3. Muted Sage Grey #A5A79B
    assert "#A5A79B" in html

    # Verify key elements
    assert "Alice" in html
    assert "Confirm Now" in html
    assert "https://logmorph.onrender.com/verify?token=xyz123" in html
    assert "This link expires in 24 hours." in html
    assert "LogMorph" in html


def test_build_professional_email_html_contains_telemetry_svg_logo():
    """Verify that generated email HTML includes the telemetry vector logo."""
    html = _build_professional_email_html(
        preheader="Logo check",
        headline="Welcome",
        recipient_name="Bob",
        lead_text="Welcome to the telemetry platform.",
    )

    # Check for SVG mark and palette accents inside the logo container
    assert "<svg" in html
    assert 'background-color: #590907' in html
    assert 'fill="#E8D2B5"' in html
    assert 'fill="#A5A79B"' in html


@pytest.mark.asyncio
async def test_email_service_verification_email_palette():
    """Verify send_verification_email generates HTML with the new branding palette."""
    service = get_email_service()
    service.sent_emails.clear()

    await service.send_verification_email(
        to_email="developer@example.com",
        full_name="Alex Developer",
        raw_token="mock_verify_token_999",
    )

    assert len(service.sent_emails) == 1
    sent = service.sent_emails[0]
    assert sent["to"] == "developer@example.com"
    assert "Verify your LogMorph account" in sent["subject"]

    html = sent["html"]
    assert "#590907" in html
    assert "#E8D2B5" in html
    assert "#A5A79B" in html
    assert "Verify email address" in html


@pytest.mark.asyncio
async def test_email_service_password_reset_email_palette():
    """Verify send_password_reset_email generates HTML with the new branding palette."""
    service = get_email_service()
    service.sent_emails.clear()

    await service.send_password_reset_email(
        to_email="admin@example.com",
        full_name="Admin User",
        raw_token="mock_reset_token_888",
    )

    assert len(service.sent_emails) == 1
    sent = service.sent_emails[0]
    assert sent["to"] == "admin@example.com"
    assert "Reset your LogMorph password" in sent["subject"]

    html = sent["html"]
    assert "#590907" in html
    assert "#E8D2B5" in html
    assert "#A5A79B" in html
    assert "Reset password" in html


@pytest.mark.asyncio
async def test_email_service_password_changed_notification():
    """Verify send_password_changed_notification dispatches cleanly."""
    service = get_email_service()
    service.sent_emails.clear()

    await service.send_password_changed_notification(
        to_email="admin@example.com",
        full_name="Admin User",
    )

    assert len(service.sent_emails) == 1
    sent = service.sent_emails[0]
    assert sent["to"] == "admin@example.com"
    assert "Security Notice: Your LogMorph password has been changed" in sent["subject"]
    assert "#590907" in sent["html"]
