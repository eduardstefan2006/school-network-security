"""
Modul pentru trimiterea notificărilor Telegram la alertele IDS critice.
Implementează rate limiting pentru a evita spam-ul și gestionează erorile fără
a bloca thread-ul principal de captură.
"""
import threading
import time
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Severitățile în ordine crescătoare
_SEVERITY_ORDER = ['low', 'medium', 'high', 'critical']

# Emoji-uri pentru fiecare severitate
_SEVERITY_EMOJI = {
    'critical': '🔴',
    'high': '🟠',
    'medium': '🟡',
    'low': '🟢',
}

# Cache pentru rate limiting: cheie -> timestamp ultima notificare
# Cheie: (source_ip, alert_type)
_rate_limit_cache: dict = {}
_rate_limit_lock = threading.Lock()

# Interval minim între notificări pentru același (source_ip, alert_type), în secunde
_RATE_LIMIT_SECONDS = 300  # 5 minute


def _is_rate_limited(source_ip: str, alert_type: str) -> bool:
    """Verifică dacă notificarea este limitată de rata de trimitere."""
    key = (source_ip, alert_type)
    now = time.monotonic()
    with _rate_limit_lock:
        last_sent = _rate_limit_cache.get(key)
        if last_sent is not None and (now - last_sent) < _RATE_LIMIT_SECONDS:
            return True
        _rate_limit_cache[key] = now
        return False


def _format_message(alert_data: dict) -> str:
    """Formatează mesajul de notificare în format HTML pentru Telegram."""
    severity = alert_data.get('severity', 'medium').lower()
    emoji = _SEVERITY_EMOJI.get(severity, '⚪')
    severity_label = severity.upper()

    alert_type = alert_data.get('alert_type', 'Necunoscut')
    source_ip = alert_data.get('source_ip', 'N/A')
    destination_ip = alert_data.get('destination_ip') or 'N/A'
    port = alert_data.get('port')
    message = alert_data.get('message', '')

    # Formatăm timestamp-ul
    ts = alert_data.get('timestamp')
    if ts:
        if hasattr(ts, 'strftime'):
            timestamp_str = ts.strftime('%d.%m.%Y %H:%M:%S')
        else:
            timestamp_str = str(ts)
    else:
        timestamp_str = datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M:%S')

    lines = [
        f'{emoji} <b>ALERTĂ {severity_label} - SchoolSec</b>',
        '',
        f'<b>Tip:</b> {alert_type}',
        f'<b>IP Sursă:</b> {source_ip}',
        f'<b>IP Destinație:</b> {destination_ip}',
    ]

    if port:
        lines.append(f'<b>Port:</b> {port}')

    lines += [
        f'<b>Mesaj:</b> {message}',
        f'<b>Timestamp:</b> {timestamp_str}',
        '',
        '🏫 SchoolSec - Școala 2 Liești',
    ]

    return '\n'.join(lines)


def _send_telegram(token: str, chat_id: str, text: str) -> bool:
    """
    Trimite un mesaj prin Telegram Bot API.
    Returnează True la succes, False la eroare.
    """
    try:
        import requests  # noqa: PLC0415
    except ImportError:
        logger.error('[Telegram] Biblioteca requests nu este instalată.')
        return False

    url = f'https://api.telegram.org/bot{token}/sendMessage'
    payload = {
        'chat_id': chat_id,
        'text': text,
        'parse_mode': 'HTML',
    }
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code == 200:
            return True
        logger.warning(
            '[Telegram] Răspuns neașteptat de la API: %s %s',
            response.status_code,
            response.text,
        )
        return False
    except Exception as exc:
        logger.warning('[Telegram] Eroare la trimiterea notificării: %s', exc)
        return False


def _severity_index(severity: str) -> int:
    """Returnează indexul numeric al severității (mai mare = mai sever)."""
    try:
        return _SEVERITY_ORDER.index(severity.lower())
    except ValueError:
        return 0


def send_alert_notification(alert_data: dict, app_config: dict) -> None:
    """
    Trimite o notificare Telegram pentru o alertă IDS dacă sunt îndeplinite
    condițiile de configurare și rata de trimitere.

    Această funcție este sigură de apelat din orice thread — nu aruncă niciodată
    excepții și nu blochează thread-ul apelant (trimite în fundal).

    :param alert_data: Dicționar cu datele alertei (alert_type, source_ip, severity, etc.)
    :param app_config: Dicționar cu configurația aplicației Flask (app.config)
    """
    try:
        if not app_config.get('TELEGRAM_ENABLED', False):
            return

        token = app_config.get('TELEGRAM_BOT_TOKEN', '')
        chat_id = app_config.get('TELEGRAM_CHAT_ID', '')
        if not token or not chat_id:
            return

        min_severity = app_config.get('TELEGRAM_MIN_SEVERITY', 'high').lower()
        alert_severity = alert_data.get('severity', 'low').lower()

        if _severity_index(alert_severity) < _severity_index(min_severity):
            return

        source_ip = alert_data.get('source_ip', '')
        alert_type = alert_data.get('alert_type', '')

        if _is_rate_limited(source_ip, alert_type):
            logger.debug(
                '[Telegram] Rate limit activ pentru %s / %s, notificare omisă.',
                source_ip,
                alert_type,
            )
            return

        message = _format_message(alert_data)

        # Trimitem în fundal pentru a nu bloca thread-ul de procesare pachete
        t = threading.Thread(
            target=_send_telegram,
            args=(token, chat_id, message),
            daemon=True,
        )
        t.start()

    except Exception as exc:
        # Nu permitem niciodată ca o eroare de notificare să afecteze snifferul
        logger.warning('[Telegram] Eroare neașteptată în send_alert_notification: %s', exc)
