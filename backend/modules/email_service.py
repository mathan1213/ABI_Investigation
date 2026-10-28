import smtplib
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
from config import settings


def _send_welcome_email_sync(to_email: str, user_name: str) -> bool:
    """
    Synchronous helper that attempts to deliver a Welcome email via Gmail SMTP (STARTTLS).
    Wrapped in try/except so email delivery errors never propagate to the caller.
    """
    smtp_email = settings.SMTP_EMAIL or settings.SMTP_USER
    smtp_password = settings.SMTP_APP_PASSWORD or settings.SMTP_PASSWORD
    smtp_host = settings.SMTP_HOST or "smtp.gmail.com"
    smtp_port = settings.SMTP_PORT or 587
    sender = settings.SMTP_FROM or smtp_email or "noreply@breach-investigation.local"

    subject = f"Welcome to {settings.APP_NAME} - Your Account is Ready"
    name_display = user_name.strip() if user_name else "User"

    text_body = (
        f"Hello {name_display},\n\n"
        f"Welcome to {settings.APP_NAME}! Your account has been successfully created.\n\n"
        f"You can now sign in at any time with your email and password to run security audits "
        f"and track incident investigations.\n\n"
        f"If you did not create this account, please contact system administration immediately.\n\n"
        f"Best regards,\n"
        f"{settings.APP_NAME} Team\n"
    )

    html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0b1220; color: #f8fafc; padding: 30px 15px; margin: 0;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr>
      <td align="center">
        <table width="100%" style="max-width: 500px; background-color: #111827; border: 1px solid #1e293b; border-radius: 16px; padding: 28px; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
          <tr>
            <td align="center" style="padding-bottom: 16px;">
              <h2 style="margin: 0; color: #38bdf8; font-size: 22px; font-weight: 700;">{settings.APP_NAME}</h2>
              <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 13px;">Security &amp; Incident Forensics</p>
            </td>
          </tr>
          <tr>
            <td style="padding: 20px 0; border-top: 1px solid #1e293b; border-bottom: 1px solid #1e293b;">
              <h3 style="color: #38bdf8; margin: 0 0 12px 0; font-size: 18px;">Welcome, {name_display}!</h3>
              <p style="color: #cbd5e1; font-size: 14px; line-height: 1.6; margin: 0 0 16px 0;">
                Your account has been created successfully. You can now log in using your registered email address and password.
              </p>
              <div style="background-color: #0b0f19; border: 1px solid #0284c7; border-radius: 12px; padding: 14px 18px; margin: 16px 0;">
                <p style="margin: 0; color: #94a3b8; font-size: 12px;">Registered Email:</p>
                <p style="margin: 4px 0 0 0; color: #f0f9ff; font-family: monospace; font-size: 14px; font-weight: 600;">{to_email}</p>
              </div>
              <p style="color: #94a3b8; font-size: 13px; margin: 16px 0 0 0; line-height: 1.5;">
                Start inspecting your Telegram export logs, public repositories, and IP/DNS records for credentials and breach exposures.
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding-top: 18px; text-align: center;">
              <p style="color: #64748b; font-size: 12px; margin: 0; line-height: 1.4;">
                If you did not create this account, please contact your security team.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    # If SMTP credentials are not configured, simulate delivery safely
    if not smtp_email or not smtp_password:
        print(f"[WELCOME EMAIL] SMTP credentials not set; welcome email simulated for {to_email}")
        return True

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = to_email

        part1 = MIMEText(text_body, "plain", "utf-8")
        part2 = MIMEText(html_body, "html", "utf-8")
        msg.attach(part1)
        msg.attach(part2)

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            server.login(smtp_email, smtp_password)
            server.sendmail(sender, [to_email], msg.as_string())

        print(f"[WELCOME EMAIL] Successfully delivered welcome email to {to_email}")
        return True
    except Exception as e:
        print(f"[WELCOME EMAIL WARNING] Failed to deliver email to {to_email}: {e}")
        return False


def send_welcome_email(to_email: str, user_name: str = "") -> None:
    """
    Sends a welcome email notification asynchronously in a background thread.
    Never blocks the caller and never raises exceptions on SMTP failure.
    """
    try:
        thread = threading.Thread(
            target=_send_welcome_email_sync,
            args=(to_email, user_name),
            daemon=True
        )
        thread.start()
    except Exception as e:
        print(f"[WELCOME EMAIL BACKGROUND ERROR] {e}")
