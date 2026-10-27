import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
from fastapi import HTTPException, status
from config import settings

PURPOSE_PHRASES = {
    "register": "complete your registration",
    "login": "sign in to your account",
    "admin_login": "sign in to the administrative portal",
    "password_reset": "reset your password",
}

def send_otp_email(to_email: str, code: str, purpose: str = "login") -> bool:
    """
    Sends a 6-digit OTP email using SMTP with STARTTLS.
    If SMTP is unconfigured and APP_ENV is development, prints the code to stdout only.
    Otherwise raises 503 Service Unavailable.
    Never exposes the code in any API response.
    """
    action_phrase = PURPOSE_PHRASES.get(purpose, "verify your account")
    subject = f"[{settings.APP_NAME}] Your verification code"

    text_body = (
        f"{settings.APP_NAME}\n\n"
        f"Your verification code is: {code}\n\n"
        f"This code expires in 10 minutes.\n"
        f"If you did not request this, ignore this email.\n"
    )

    html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0b1220; color: #f8fafc; padding: 30px 15px; margin: 0;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr>
      <td align="center">
        <table width="100%" style="max-width: 480px; background-color: #111827; border: 1px solid #1e293b; border-radius: 16px; padding: 28px; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
          <tr>
            <td align="center" style="padding-bottom: 16px;">
              <h2 style="margin: 0; color: #38bdf8; font-size: 20px; font-weight: 700;">{settings.APP_NAME}</h2>
              <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 13px;">Security &amp; Incident Forensics</p>
            </td>
          </tr>
          <tr>
            <td style="padding: 16px 0; border-top: 1px solid #1e293b; border-bottom: 1px solid #1e293b;">
              <p style="color: #cbd5e1; font-size: 14px; margin: 0 0 16px 0;">Use the 6-digit verification code below to {action_phrase}:</p>
              <div style="background-color: #0b0f19; border: 1px solid #0284c7; border-radius: 12px; padding: 18px; text-align: center; margin: 16px 0;">
                <span style="font-family: 'Courier New', Courier, monospace; font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #38bdf8;">{code}</span>
              </div>
              <p style="color: #94a3b8; font-size: 12px; margin: 12px 0 0 0; text-align: center;">This code <strong>expires in 10 minutes</strong>.</p>
            </td>
          </tr>
          <tr>
            <td style="padding-top: 18px; text-align: center;">
              <p style="color: #64748b; font-size: 12px; margin: 0; line-height: 1.4;">If you did not request this, ignore this email. Your account remains secure.</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    if settings.SMTP_HOST and settings.SMTP_HOST.strip():
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = settings.SMTP_FROM
            msg["To"] = to_email

            part1 = MIMEText(text_body, "plain", "utf-8")
            part2 = MIMEText(html_body, "html", "utf-8")
            msg.attach(part1)
            msg.attach(part2)

            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
                server.starttls()
                if settings.SMTP_USER and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.sendmail(settings.SMTP_FROM, [to_email], msg.as_string())
            return True
        except Exception as e:
            # When SMTP fails, check if dev fallback applies
            is_dev = settings.APP_ENV.lower() in ("development", "dev") or settings.ENVIRONMENT.lower() in ("development", "dev")
            if is_dev:
                print(f"[DEV ONLY] OTP for {to_email} ({purpose}): {code}")
                return True
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Email delivery service is currently unavailable. Please contact the administrator."
            )

    # SMTP not configured
    is_dev = settings.APP_ENV.lower() in ("development", "dev") or settings.ENVIRONMENT.lower() in ("development", "dev")
    if is_dev:
        print(f"[DEV ONLY] OTP for {to_email} ({purpose}): {code}")
        return True
    else:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email delivery service is currently unavailable. Please contact the administrator."
        )
