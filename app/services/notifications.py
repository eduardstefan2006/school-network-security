"""
Serviciu de notificări pentru administratorii sistemului.
Suportă Telegram, email și notificări în dashboard.
"""
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


def notify_admins(message, alert_level='INFO', channels=None):
    """Trimite notificări tuturor administratorilor prin canalele specificate."""
    if channels is None:
        channels = ['telegram', 'dashboard']

    if 'telegram' in channels:
        send_telegram_alert(message, alert_level)

    if 'email' in channels:
        send_email_alert(message, alert_level)

    if 'dashboard' in channels:
        create_dashboard_notification(message, alert_level)


def send_telegram_alert(message, level='INFO'):
    """Trimite alertă prin Telegram Bot API."""
    try:
        from flask import current_app
        import requests

        token = current_app.config.get('TELEGRAM_BOT_TOKEN')
        chat_id = current_app.config.get('TELEGRAM_CHAT_ID')

        if not token or not chat_id:
            return False

        url = f'https://api.telegram.org/bot{token}/sendMessage'
        payload = {
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'HTML',
        }

        response = requests.post(url, json=payload, timeout=10)
        return response.status_code == 200
    except Exception as e:
        logger.error(f"Error sending Telegram alert: {e}")
        return False


def send_email_alert(message, level='INFO'):
    """Trimite alertă prin email (dacă Flask-Mail este configurat)."""
    try:
        from flask import current_app
        from flask_mail import Mail, Message as MailMessage

        subject = f"[SchoolSec] {level} Alert - Disk Space"
        recipients = current_app.config.get('ADMIN_EMAILS', [])

        if not recipients:
            return False

        msg = MailMessage(subject, recipients=recipients, body=message)
        mail = Mail(current_app)
        mail.send(msg)
        return True
    except Exception as e:
        logger.error(f"Error sending email alert: {e}")
        return False


def create_dashboard_notification(message, level='INFO'):
    """Creează o notificare în dashboard (stocată în baza de date)."""
    try:
        from app import db
        from app.models import SystemNotification

        notification = SystemNotification(
            message=message,
            level=level,
            created_at=datetime.now(timezone.utc)
        )
        db.session.add(notification)
        db.session.commit()
        return True
    except Exception as e:
        logger.error(f"Error creating dashboard notification: {e}")
        return False
