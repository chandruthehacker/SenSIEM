import os
import smtplib
from email.message import EmailMessage
import ssl
import requests

from backend.configs.config import load_config

# 1. Send Email Notification
def send_email_notification(alert: dict, email_config: dict):

    try:
        msg = EmailMessage()
        msg["Subject"] = f"[ALERT] {alert.get('rule_name', 'N/A')} - {alert.get('severity', 'N/A')}"
        msg["From"] = email_config["sender"]
        msg["To"] = email_config["recipient"]

 # Define severity colors for better visual distinction
        severity_colors = {
            "CRITICAL": "#FF4136",  # Red
            "HIGH": "#FF851B",      # Orange
            "MEDIUM": "#FFDC00",    # Yellow
            "LOW": "#0074D9",       # Blue
            "INFO": "#2ECC40",      # Green
            "N/A": "#AAAAAA"        # Grey for unknown
        }
        alert_severity = alert.get('severity', 'N/A').upper()
        severity_color = severity_colors.get(alert_severity, "#AAAAAA")

        # Plain text version for email clients that don't support HTML
        plain_text_body = f"""
🔔 New Alert Triggered

Message: {alert.get('message', 'N/A')}

Severity: {alert.get('severity', 'N/A')}
Rule: {alert.get('rule_name', 'N/A')}
Log Level: {alert.get('log_level', 'N/A')}
Source: {alert.get('source', 'N/A')}
Host: {alert.get('host', 'N/A')}
IP: {alert.get('ip', 'N/A')}

⏱ Alert Time: {alert.get('alert_time', 'N/A')}

This is an automated alert from your system.
"""
        msg.set_content(plain_text_body)

        # HTML version with styling
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: 'Inter', sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }}
                .container {{
                    max-width: 600px;
                    margin: 20px auto;
                    background-color: #1a1a1a; /* Dark background for the card */
                    border-radius: 12px;
                    overflow: hidden;
                    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.5);
                    border: 1px solid #333;
                }}
                .header {{
                    background-color: #2a2a2a; /* Slightly lighter dark for header */
                    padding: 20px;
                    text-align: center;
                    color: #ffffff;
                    border-bottom: 1px solid #444;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 10px;
                }}
                .content {{
                    padding: 25px;
                    color: #e0e0e0; /* Light grey text */
                    line-height: 1.6;
                }}
                .detail-row {{
                    margin-bottom: 10px;
                    display: flex;
                    flex-wrap: wrap;
                }}
                .detail-label {{
                    font-weight: bold;
                    color: #999999; /* Slightly darker grey for labels */
                    width: 100px; /* Fixed width for labels */
                    flex-shrink: 0;
                }}
                .detail-value {{
                    flex-grow: 1;
                    color: #ffffff;
                }}
                .severity {{
                    font-weight: bold;
                    color: {severity_color}; /* Dynamic color based on severity */
                    text-transform: uppercase;
                }}
                .message {{
                    background-color: #222222;
                    padding: 15px;
                    border-left: 5px solid {severity_color}; /* Accent border */
                    border-radius: 8px;
                    margin-top: 15px;
                    margin-bottom: 20px;
                    font-style: italic;
                    color: #f0f0f0;
                }}
                .footer {{
                    background-color: #2a2a2a;
                    padding: 15px;
                    text-align: center;
                    color: #888888;
                    font-size: 12px;
                    border-top: 1px solid #444;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 New Alert Triggered!</h1>
                </div>
                <div class="content">
                    <div class="message">
                        <strong>Message:</strong> {alert.get('message', 'N/A')}
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Severity:</span>
                        <span class="detail-value severity">{alert.get('severity', 'N/A')}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Rule:</span>
                        <span class="detail-value">{alert.get('rule_name', 'N/A')}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Rule Type:</span>
                        <span class="detail-value">{alert.get('rule_type', 'N/A')}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Log Level:</span>
                        <span class="detail-value">{alert.get('log_level', 'N/A')}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Source:</span>
                        <span class="detail-value">{alert.get('source', 'N/A')}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Host:</span>
                        <span class="detail-value">{alert.get('host', 'N/A')}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">IP Address:</span>
                        <span class="detail-value">{alert.get('ip', 'N/A')}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Alert Time:</span>
                        <span class="detail-value">⏱ {alert.get('alert_time', 'N/A')}</span>
                    </div>
                </div>
                <div class="footer">
                    This is an automated alert from your system. Please do not reply.
                </div>
            </div>
        </body>
        </html>
        """
        msg.add_alternative(html_body, subtype="html")

        # Use SSL context for secure connection
        context = ssl.create_default_context()

        # Retrieve password from environment variable for security
        # Fallback to config if env var not set (less secure, for dev/testing)
        email_password = os.getenv("EMAIL_PASSWORD", email_config.get("password"))
        if not email_password:
            print("[ERROR] Email password not found. Please set EMAIL_PASSWORD environment variable or configure in config.")
            return

        with smtplib.SMTP(email_config["smtpServer"], int(email_config["smtpPort"])) as smtp:
            smtp.ehlo()  # Can be called before or after starttls depending on server
            smtp.starttls(context=context) # Secure the connection
            smtp.ehlo() # Re-identify after starting TLS
            smtp.login(email_config["sender"], email_password)
            smtp.send_message(msg)
        print("[INFO] Email alert sent successfully.")

    except smtplib.SMTPAuthenticationError:
        print(f"[ERROR] Failed to send email alert: Authentication failed. Check username/password for {email_config['sender']}.")
    except smtplib.SMTPConnectError as e:
        print(f"[ERROR] Failed to connect to SMTP server {email_config['smtpServer']}:{email_config['smtpPort']}: {e}")
    except smtplib.SMTPException as e:
        print(f"[ERROR] SMTP error occurred while sending email alert: {e}")
    except ValueError as e:
        print(f"[ERROR] Invalid SMTP port: {e}. Port must be a valid number.")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred while sending email alert: {e}")

# 2. Send Slack Notification
def send_slack_notification(alert: dict, slack_config: dict):
    """
    Sends a Slack notification for a triggered alert.

    Args:
        alert (dict): Dictionary containing alert details.
        slack_config (dict): Dictionary containing Slack settings (webhook).
    """
    try:
        # Retrieve webhook URL from environment variable for security
        webhook_url = os.getenv("SLACK_WEBHOOK_URL", slack_config.get("webhook")) # Corrected key to "webhook"
        if not webhook_url:
            print("[ERROR] Slack webhook URL not found. Please set SLACK_WEBHOOK_URL environment variable or configure in config.")
            return

        message = {
            "text": f":warning: *New Alert - {alert.get('rule_name', 'N/A')}*\n"
                    f"Severity: {alert.get('severity', 'N/A')}\n"
                    f"Message: {alert.get('message', 'N/A')}"
        }
        response = requests.post(webhook_url, json=message, timeout=10) # Added timeout
        response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)
        print("[INFO] Slack alert sent successfully.")
    except requests.HTTPError as e:
        print(f"[ERROR] Failed to send Slack alert (HTTP Error): {e.response.status_code} - {e.response.text}")
    except requests.RequestException as e:
        print(f"[ERROR] Failed to send Slack alert (Network Error): {e}")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred while sending Slack alert: {e}")

# 3. Send Telegram Notification
def send_telegram_notification(alert: dict, telegram_config: dict):
    """
    Sends a Telegram notification for a triggered alert.

    Args:
        alert (dict): Dictionary containing alert details.
        telegram_config (dict): Dictionary containing Telegram settings (botToken, chatId).
    """
    try:
        # Retrieve bot token from environment variable for security
        bot_token = os.getenv("TELEGRAM_BOT_TOKEN", telegram_config.get("botToken"))
        if not bot_token:
            print("[ERROR] Telegram bot token not found. Please set TELEGRAM_BOT_TOKEN environment variable or configure in config.")
            return

        message = (
            f"🚨 *Alert*: {alert.get('rule_name', 'N/A')}\n"
            f"*Severity*: {alert.get('severity', 'N/A')}\n"
            f"Message: {alert.get('message', 'N/A')}"
        )
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {
            "chat_id": telegram_config["chatId"],
            "text": message,
            "parse_mode": "Markdown"
        }
        response = requests.post(url, data=data, timeout=10) # Added timeout
        response.raise_for_status()
        print("[INFO] Telegram alert sent successfully.")
    except requests.HTTPError as e:
        print(f"[ERROR] Failed to send Telegram alert (HTTP Error): {e.response.status_code} - {e.response.text}")
    except requests.RequestException as e:
        print(f"[ERROR] Failed to send Telegram alert (Network Error): {e}")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred while sending Telegram alert: {e}")

# 4. Get Notification Settings from config.json (UNCHANGED AS PER YOUR REQUEST)
def get_notification_settings() -> dict:
    config_data = load_config() # This loads the entire config.json
    settings = config_data.get("notificationSettings", {})
    return {
        "email": {
            "enabled": bool(settings.get("emailEnabled", False)),
            "recipient": settings.get("emailRecipient", ""),
            "sender": settings.get("emailSender", ""),
            "smtpServer": settings.get("emailSmtpServer", ""),
            "smtpPort": settings.get("emailSmtpPort", "587"),
            "password": settings.get("emailPassword", "")
        },
        "slack": {
            "enabled": bool(settings.get("slackEnabled", False)),
            "webhook": settings.get("slackWebhookUrl", "") # Note: this is 'webhook' not 'webhookUrl' in the output dict
        },
        "telegram": {
            "enabled": bool(settings.get("telegramEnabled", False)),
            "botToken": settings.get("telegramBotToken", ""),
            "chatId": settings.get("telegramChatId", "")
        }
    }

# ✅ Main Notification Dispatcher
def alert_notification(alert: dict):
    settings = get_notification_settings()

    if settings["email"]["enabled"]:
        send_email_notification(alert, settings["email"])

    if settings["slack"]["enabled"]:
        send_slack_notification(alert, settings["slack"])

    if settings["telegram"]["enabled"]:
        send_telegram_notification(alert, settings["telegram"])