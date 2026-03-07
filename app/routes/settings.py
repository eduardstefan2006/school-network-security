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


def _load_custom_whitelist():
    """Încarcă lista albă personalizată din fișier JSON."""
    try:
        os.makedirs(os.path.dirname(_WHITELIST_FILE), exist_ok=True)
        if os.path.exists(_WHITELIST_FILE):
            with open(_WHITELIST_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except OSError as e:
        logger.warning('Eroare la citirea listei albe personalizate (%s): %s', _WHITELIST_FILE, e)
    except json.JSONDecodeError as e:
        logger.warning('Fișierul listei albe personalizate este corupt (%s): %s', _WHITELIST_FILE, e)
    return []


def _save_custom_whitelist(entries):
    """Salvează lista albă personalizată în fișier JSON."""
    os.makedirs(os.path.dirname(_WHITELIST_FILE), exist_ok=True)
    with open(_WHITELIST_FILE, 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)


@settings_bp.route('/settings')
@login_required
def index():
    """Pagina de setări (doar admin)."""
    if not current_user.is_admin():
        flash('Acces interzis. Doar administratorii pot accesa setările.', 'danger')
        return redirect(url_for('dashboard.index'))

    from app.ids.rules import WHITELIST_IPS
    from app.ids.sniffer import traffic_stats

    # Configurare Telegram
    telegram_enabled = current_app.config.get('TELEGRAM_ENABLED', False)
    chat_id_raw = current_app.config.get('TELEGRAM_CHAT_ID', '')
    chat_id_masked = ('*' * (len(chat_id_raw) - 4) + chat_id_raw[-4:]) if len(chat_id_raw) > 4 else ('*' * len(chat_id_raw))

    # Lista albă
    builtin_ips = WHITELIST_IPS
    custom_entries = _load_custom_whitelist()

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
        builtin_ips=builtin_ips,
        custom_entries=custom_entries,
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
