"""
Rute pentru pagina de setări a aplicației (doar admin).
"""
import os
import json
import sys
import logging
import ipaddress
import platform
from datetime import datetime, timezone

from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user

from app import db
from app.models import Alert

settings_bp = Blueprint('settings', __name__)
logger = logging.getLogger(__name__)

# Fișierul pentru lista albă personalizată
_WHITELIST_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'whitelist_custom.json')

# Descrierile IP-urilor predefinite (folosite la migrarea automată din rules.py)
_BUILTIN_DESCRIPTIONS = {
    '127.0.0.1': 'Localhost',
    '::1': 'Localhost IPv6',
    '192.168.2.1': 'MikroTik RB3011 "Scoala 2 Liesti" - Router principal',
    '192.168.2.241': 'PiHole (server DNS)',
    '192.168.2.242': 'LibreNMS (monitorizare SNMP)',
    '192.168.2.243': 'SchoolSec (acest server)',
    '192.168.2.80': 'NVR (Network Video Recorder)',
    '192.168.2.91': 'Camera 1',
    '192.168.2.92': 'Camera 2',
    '192.168.2.93': 'Camera 3',
    '192.168.2.96': 'Camera 6',
    '192.168.2.5': 'Router Cisco',
    '192.168.2.8': 'Switch Corp A Parter',
    '192.168.2.9': 'Switch Corp A Etaj 2',
    '192.168.2.10': 'Switch Corp B',
    '192.168.2.160': 'Camera NVR Access',
    '192.168.2.161': 'Camera Etajul 1 Stanga',
    '192.168.2.162': 'Camera Parter Dreapta',
    '192.168.2.163': 'Camera Etaj Gradinita',
    '192.168.2.164': 'Camera Intrare Secretariat',
    '192.168.2.165': 'Camera Parter Stanga',
    '192.168.2.166': 'Camera Etajul 1 Dreapta',
    '192.168.2.167': 'Camera Intrare Elevi',
    '192.168.2.168': 'Camera Etaj 2 Dreapta',
    '192.168.2.169': 'Camera Etaj 2 Stanga',
    '192.168.2.170': 'Camera Sala Sport',
    '192.168.2.171': 'Camera Intrare Profesori',
    '192.168.2.172': 'Camera Teren Baschet',
    '192.168.2.173': 'Camera Intrare Elevi 2',
    '192.168.2.174': 'Camera Teren Sport',
    '192.168.2.175': 'Camera Poarta',
    '192.168.2.176': 'Camera Sala Sport intrare spate',
    '192.168.2.177': 'Camera Parter/Etajul1',
    '192.168.2.178': 'Camera Etaj1/Etaj2',
    '1.1.1.1': 'Cloudflare DNS',
    '8.8.8.8': 'Google DNS',
}


def _load_custom_whitelist():
    """Încarcă lista albă personalizată din fișier JSON.

    La prima rulare (fișierul nu există), migrează automat IP-urile predefinite
    din WHITELIST_IPS în fișierul JSON.
    """
    from app.ids.rules import WHITELIST_IPS as _BUILTIN_IPS

    try:
        os.makedirs(os.path.dirname(_WHITELIST_FILE), exist_ok=True)
        if os.path.exists(_WHITELIST_FILE):
            with open(_WHITELIST_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except OSError as e:
        logger.warning('Eroare la citirea listei albe personalizate (%s): %s', _WHITELIST_FILE, e)
        return []
    except json.JSONDecodeError as e:
        logger.warning('Fișierul listei albe personalizate este corupt (%s): %s', _WHITELIST_FILE, e)
        return []

    # Fișierul nu există – migrare IP-uri predefinite la prima rulare
    entries = [
        {'ip': ip, 'description': _BUILTIN_DESCRIPTIONS.get(ip, ''), 'builtin': True}
        for ip in _BUILTIN_IPS
    ]
    try:
        _save_custom_whitelist(entries)
        logger.info('IP-urile predefinite au fost migrate în %s', _WHITELIST_FILE)
    except OSError as e:
        logger.warning('Eroare la salvarea migrării listei albe (%s): %s', _WHITELIST_FILE, e)
    return entries


def _save_custom_whitelist(entries):
    """Salvează lista albă personalizată în fișier JSON."""
    os.makedirs(os.path.dirname(_WHITELIST_FILE), exist_ok=True)
    with open(_WHITELIST_FILE, 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
    # Invalidăm cache-ul din detector după fiecare modificare
    try:
        from app.ids.detector import invalidate_whitelist_cache
        invalidate_whitelist_cache()
    except Exception:
        pass


@settings_bp.route('/settings')
@login_required
def index():
    """Pagina de setări (doar admin)."""
    if not current_user.is_admin():
        flash('Acces interzis. Doar administratorii pot accesa setările.', 'danger')
        return redirect(url_for('dashboard.index'))

    from app.ids.sniffer import traffic_stats

    # Configurare Telegram
    telegram_enabled = current_app.config.get('TELEGRAM_ENABLED', False)
    chat_id_raw = current_app.config.get('TELEGRAM_CHAT_ID', '')
    chat_id_masked = ('*' * (len(chat_id_raw) - 4) + chat_id_raw[-4:]) if len(chat_id_raw) > 4 else ('*' * len(chat_id_raw))

    # Lista albă (toate IP-urile, inclusiv cele migrate din rules.py)
    whitelist_entries = _load_custom_whitelist()

    # Informații sistem
    db_path = current_app.config.get('SQLALCHEMY_DATABASE_URI', '').replace('sqlite:///', '')
    if db_path and not os.path.isabs(db_path):
        db_path = os.path.join(os.path.dirname(current_app.root_path), db_path)
    try:
        db_size_bytes = os.path.getsize(db_path) if db_path and os.path.exists(db_path) else 0
        db_size = f"{db_size_bytes / 1024:.1f} KB"
    except OSError:
        db_size = 'N/A'

    total_alerts = Alert.query.count()
    sniffer_mode = current_app.config.get('SNIFFER_MODE', 'simulated')

    start_time_str = traffic_stats.get('start_time', '') if isinstance(traffic_stats, dict) else ''
    try:
        start_time = datetime.fromisoformat(start_time_str)
        uptime_seconds = int((datetime.now(timezone.utc) - start_time).total_seconds())
        hours, remainder = divmod(uptime_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        uptime = f"{hours}h {minutes}m {seconds}s"
    except (ValueError, TypeError):
        uptime = 'N/A'

    system_info = {
        'version': '1.0.0',
        'uptime': uptime,
        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        'db_size': db_size,
        'total_alerts': total_alerts,
        'sniffer_mode': sniffer_mode,
    }

    return render_template(
        'settings.html',
        telegram_enabled=telegram_enabled,
        chat_id_masked=chat_id_masked,
        whitelist_entries=whitelist_entries,
        system_info=system_info,
    )


@settings_bp.route('/api/settings/whitelist', methods=['GET'])
@login_required
def get_whitelist():
    """Returnează lista albă personalizată ca JSON."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis.'}), 403
    return jsonify(_load_custom_whitelist())


@settings_bp.route('/api/settings/whitelist/add', methods=['POST'])
@login_required
def add_whitelist_ip():
    """Adaugă un IP în lista albă personalizată."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis.'}), 403

    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    description = data.get('description', '').strip()

    if not ip:
        return jsonify({'error': 'Adresa IP este obligatorie.'}), 400

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({'error': f'Adresa IP "{ip}" nu este validă.'}), 400

    entries = _load_custom_whitelist()
    if any(e.get('ip') == ip for e in entries):
        return jsonify({'error': f'IP-ul {ip} este deja în lista albă.'}), 409

    entries.append({'ip': ip, 'description': description})
    _save_custom_whitelist(entries)
    return jsonify({'success': True, 'message': f'IP-ul {ip} a fost adăugat în lista albă.'})


@settings_bp.route('/api/settings/whitelist/remove', methods=['POST'])
@login_required
def remove_whitelist_ip():
    """Elimină un IP din lista albă personalizată."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis.'}), 403

    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()

    if not ip:
        return jsonify({'error': 'Adresa IP este obligatorie.'}), 400

    entries = _load_custom_whitelist()
    new_entries = [e for e in entries if e.get('ip') != ip]
    if len(new_entries) == len(entries):
        return jsonify({'error': f'IP-ul {ip} nu a fost găsit în lista albă personalizată.'}), 404

    _save_custom_whitelist(new_entries)
    return jsonify({'success': True, 'message': f'IP-ul {ip} a fost eliminat din lista albă.'})
