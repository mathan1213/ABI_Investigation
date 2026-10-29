import html
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional, Tuple
from config import settings

EMAIL_SUBJECT = "Welcome to Account Breach Investigation — Registration Successful"


def generate_email_bodies(to_email: str, user_name: str) -> Tuple[str, str]:
    """Generates the required plain-text and HTML bodies for the registration confirmation email."""
    name_display = user_name.strip() if user_name and user_name.strip() else "User"
    escaped_name = html.escape(name_display)
    escaped_email = html.escape(to_email)

    text_body = (
        f"Hello {name_display},\n\n"
        f"Welcome to Account Breach Investigation!\n\n"
        f"Your account has been successfully registered.\n\n"
        f"You can now use your account to access the Account Breach Investigation platform "
        f"and its security investigation features, including:\n\n"
        f"- Telegram Account Investigation\n"
        f"- Repository URL Security Check\n"
        f"- Network IP Address Investigation\n\n"
        f"Thank you for joining us.\n\n"
        f"Best regards,\n"
        f"Account Breach Investigation Team\n"
    )

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{EMAIL_SUBJECT}</title>
</head>
<body style="margin: 0; padding: 32px 16px; background-color: #0b1220; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f1f5f9; line-height: 1.6;">
  <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width: 580px; background-color: #111827; border: 1px solid #1e293b; border-radius: 16px; box-shadow: 0 15px 35px rgba(0, 0, 0, 0.45); overflow: hidden;" border="0" cellspacing="0" cellpadding="0">
          <!-- Header -->
          <tr>
            <td style="padding: 32px 32px 20px 32px; border-bottom: 1px solid #1e293b; background: linear-gradient(180deg, #131d33 0%, #111827 100%);">
              <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td>
                    <div style="display: inline-block; padding: 6px 12px; background-color: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 8px; color: #38bdf8; font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;">
                      Security &amp; Forensics Platform
                    </div>
                    <h1 style="margin: 14px 0 4px 0; color: #ffffff; font-size: 20px; font-weight: 700; letter-spacing: -0.02em;">
                      Account Breach Investigation
                    </h1>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Main Content -->
          <tr>
            <td style="padding: 32px;">
              <p style="margin: 0 0 16px 0; color: #e2e8f0; font-size: 15px;">
                Hello <strong>{escaped_name}</strong>,
              </p>

              <p style="margin: 0 0 16px 0; color: #e2e8f0; font-size: 15px;">
                Welcome to <strong>Account Breach Investigation</strong>!
              </p>

              <div style="margin: 20px 0; padding: 14px 18px; background-color: #0b0f19; border: 1px solid #0284c7; border-radius: 10px;">
                <p style="margin: 0; color: #38bdf8; font-size: 14px; font-weight: 600;">
                  Your account has been successfully registered.
                </p>
                <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 12px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;">
                  Registered email: {escaped_email}
                </p>
              </div>

              <p style="margin: 0 0 14px 0; color: #cbd5e1; font-size: 14px;">
                You can now use your account to access the Account Breach Investigation platform and its security investigation features, including:
              </p>

              <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="margin: 12px 0 24px 0;">
                <tr>
                  <td style="padding: 10px 14px; background-color: #0d1527; border: 1px solid #1e293b; border-radius: 8px; margin-bottom: 8px;">
                    <span style="color: #38bdf8; font-weight: bold; margin-right: 8px;">&bull;</span>
                    <strong style="color: #f1f5f9; font-size: 13px;">Telegram Account Investigation</strong>
                    <span style="display: block; color: #94a3b8; font-size: 12px; margin-top: 2px;">Inspect chat session dumps, verify sensitive code maskings, and analyze unauthorized activity indicators.</span>
                  </td>
                </tr>
                <tr><td style="height: 8px;"></td></tr>
                <tr>
                  <td style="padding: 10px 14px; background-color: #0d1527; border: 1px solid #1e293b; border-radius: 8px; margin-bottom: 8px;">
                    <span style="color: #38bdf8; font-weight: bold; margin-right: 8px;">&bull;</span>
                    <strong style="color: #f1f5f9; font-size: 13px;">Repository URL Security Check</strong>
                    <span style="display: block; color: #94a3b8; font-size: 12px; margin-top: 2px;">Scan public git repositories for leaked private keys, API secrets, and suspicious automation scripts.</span>
                  </td>
                </tr>
                <tr><td style="height: 8px;"></td></tr>
                <tr>
                  <td style="padding: 10px 14px; background-color: #0d1527; border: 1px solid #1e293b; border-radius: 8px;">
                    <span style="color: #38bdf8; font-weight: bold; margin-right: 8px;">&bull;</span>
                    <strong style="color: #f1f5f9; font-size: 13px;">Network IP Address Investigation</strong>
                    <span style="display: block; color: #94a3b8; font-size: 12px; margin-top: 2px;">Analyze server IPs, domain DNS records, SSL certifications, and threat abuse scores in plain English.</span>
                  </td>
                </tr>
              </table>

              <p style="margin: 0 0 20px 0; color: #e2e8f0; font-size: 14px;">
                Thank you for joining us.
              </p>

              <p style="margin: 0; color: #cbd5e1; font-size: 14px; line-height: 1.5;">
                Best regards,<br>
                <strong style="color: #ffffff;">Account Breach Investigation Team</strong>
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding: 20px 32px; background-color: #0b0f19; border-top: 1px solid #1e293b; text-align: center;">
              <p style="margin: 0; color: #64748b; font-size: 11px;">
                This notification was sent to {escaped_email}. If you did not initiate this registration, please contact your security administrator.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    return text_body, html_body


def send_welcome_email(to_email: str, user_name: str = "") -> Tuple[bool, Optional[str]]:
    """
    Sends a professional registration confirmation email to the user via Gmail SMTP (STARTTLS).
    
    Reads credentials from environment variables:
      - SMTP_EMAIL or SMTP_USER
      - SMTP_PASSWORD or SMTP_APP_PASSWORD
      - SMTP_HOST (defaults to smtp.gmail.com)
      - SMTP_PORT (defaults to 587)
    
    Returns:
      (True, None) if the email was successfully dispatched.
      (False, error_reason) if SMTP is unconfigured or if transmission failed.
    
    Secrets (passwords, tokens) are NEVER logged.
    """
    smtp_email = settings.smtp_username
    smtp_password = settings.smtp_pass
    smtp_host = settings.SMTP_HOST or "smtp.gmail.com"
    smtp_port = settings.SMTP_PORT or 587
    sender = settings.SMTP_FROM or smtp_email or "noreply@breach-investigation.local"

    # Check for SMTP configuration
    if not smtp_email or not smtp_password:
        print(
            f"[EMAIL CONFIGURATION ERROR] SMTP is not configured. "
            f"Please set SMTP_EMAIL and SMTP_PASSWORD in backend/.env to enable welcome email delivery to {to_email}."
        )
        return False, "SMTP credentials are not configured"

    try:
        text_body, html_body = generate_email_bodies(to_email, user_name)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = EMAIL_SUBJECT
        msg["From"] = sender
        msg["To"] = to_email

        part1 = MIMEText(text_body, "plain", "utf-8")
        part2 = MIMEText(html_body, "html", "utf-8")
        msg.attach(part1)
        msg.attach(part2)

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(smtp_email, smtp_password)
            server.sendmail(sender, [to_email], msg.as_string())

        print(f"[EMAIL SENT] Registration confirmation email successfully sent to {to_email}")
        return True, None

    except smtplib.SMTPAuthenticationError as e:
        err_msg = "SMTP authentication failed. Please check your Gmail address and 16-character App Password."
        print(f"[EMAIL DELIVERY ERROR] Authentication failed for {to_email}: {err_msg}")
        return False, err_msg
    except smtplib.SMTPException as e:
        err_msg = f"SMTP protocol error: {e.__class__.__name__}"
        print(f"[EMAIL DELIVERY ERROR] Failed to send email to {to_email}: {err_msg}")
        return False, err_msg
    except Exception as e:
        err_msg = f"{e.__class__.__name__}: {str(e)}"
        print(f"[EMAIL DELIVERY ERROR] Unexpected error while sending email to {to_email}: {e.__class__.__name__}")
        return False, err_msg
