"""
Rute pentru configurarea și testarea notificărilor Telegram.
"""
from flask import Blueprint, jsonify, current_app
from flask_login import login_required, current_user

telegram_bp = Blueprint('telegram', __name__)


@telegram_bp.route('/api/telegram/test', methods=['POST'])
@login_required
def test_notification():
    """
    Trimite o notificare de test pe Telegram pentru a verifica configurația.
    Accesibil doar pentru administratori.
    """
    if not current_user.is_admin():
        return jsonify({'success': False, 'error': 'Acces interzis. Doar administratorii pot trimite notificări de test.'}), 403

    if not current_app.config.get('TELEGRAM_ENABLED', False):
        return jsonify({'success': False, 'error': 'Notificările Telegram sunt dezactivate. Setați TELEGRAM_ENABLED=true.'}), 400

    token = current_app.config.get('TELEGRAM_BOT_TOKEN', '')
    chat_id = current_app.config.get('TELEGRAM_CHAT_ID', '')

    if not token or not chat_id:
        return jsonify({'success': False, 'error': 'TELEGRAM_BOT_TOKEN sau TELEGRAM_CHAT_ID nu sunt configurate.'}), 400

    from app.notifications.telegram import _send_telegram, _format_message
    from datetime import datetime, timezone

    test_alert = {
        'alert_type': 'Test Notificare',
        'source_ip': '127.0.0.1',
        'destination_ip': '192.168.1.1',
        'port': 0,
        'message': 'Aceasta este o notificare de test trimisă din panoul SchoolSec.',
        'severity': 'high',
        'timestamp': datetime.now(timezone.utc),
    }

    message = _format_message(test_alert)
    success = _send_telegram(token, chat_id, message)

    if success:
        return jsonify({'success': True, 'message': 'Notificarea de test a fost trimisă cu succes pe Telegram.'})
    return jsonify({'success': False, 'error': 'Nu s-a putut trimite notificarea. Verificați token-ul și chat_id-ul.'}), 502
