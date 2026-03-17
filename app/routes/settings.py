"""
Rute pentru pagina de setări a aplicației (doar admin).
"""
import os
import json
import sys
import logging
import ipaddress
import hashlib
import base64
import platform
from datetime import datetime, timezone

from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user

from app import db
from app.models import Alert, SecurityLog

settings_bp = Blueprint('settings', __name__)
logger = logging.getLogger(__name__)

# Fișierul pentru lista albă personalizată
_WHITELIST_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'whitelist_custom.json')

# Fișierul pentru configurația persistentă Telegram
_TELEGRAM_CONFIG_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'telegram_config.json')

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


def _get_telegram_enabled():
    """Returnează starea persistentă a notificărilor Telegram.

    Citește din fișierul JSON de configurare; dacă nu există,
    folosește valoarea din variabila de mediu (app.config).
    """
    try:
        if os.path.exists(_TELEGRAM_CONFIG_FILE):
            with open(_TELEGRAM_CONFIG_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            enabled = bool(data.get('enabled', False))
            # Sincronizăm și app.config pentru a fi folosit de notificări
            current_app.config['TELEGRAM_ENABLED'] = enabled
            return enabled
    except (OSError, json.JSONDecodeError) as e:
        logger.warning('Eroare la citirea configurației Telegram (%s): %s', _TELEGRAM_CONFIG_FILE, e)
    return current_app.config.get('TELEGRAM_ENABLED', False)


def _set_telegram_enabled(enabled: bool):
    """Salvează starea notificărilor Telegram în fișierul persistent și actualizează app.config."""
    try:
        os.makedirs(os.path.dirname(_TELEGRAM_CONFIG_FILE), exist_ok=True)
        with open(_TELEGRAM_CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump({'enabled': enabled}, f)
    except OSError as e:
        logger.warning('Eroare la salvarea configurației Telegram (%s): %s', _TELEGRAM_CONFIG_FILE, e)
    current_app.config['TELEGRAM_ENABLED'] = enabled


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


# =============================================================================
# Utilitare criptare Fernet pentru parola MikroTik
# =============================================================================

def _get_fernet():
    """Returnează o instanță Fernet cu cheia derivată din SECRET_KEY."""
    from cryptography.fernet import Fernet
    secret = current_app.config['SECRET_KEY'].encode()
    key_bytes = hashlib.sha256(secret).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(fernet_key)


def _encrypt_password(password: str) -> str:
    """Criptează parola și returnează string-ul criptat."""
    return _get_fernet().encrypt(password.encode()).decode()


def _decrypt_password(encrypted: str) -> str:
    """Decriptează parola criptată."""
    return _get_fernet().decrypt(encrypted.encode()).decode()


def _get_mikrotik_config():
    """Returnează configurația MikroTik din baza de date.

    Returnează un dict cu cheile: host, port, username, password, enabled,
    updated_by, updated_at. Dacă nu există înregistrare în BD, returnează None.
    """
    from app.models import MikroTikConfig
    cfg = db.session.get(MikroTikConfig, 1)
    if cfg is None:
        return None
    password = ''
    if cfg.password_encrypted:
        try:
            password = _decrypt_password(cfg.password_encrypted)
        except Exception:
            logger.warning('[MikroTik Settings] Eroare la decriptarea parolei.')
    return {
        'host': cfg.host,
        'port': cfg.port,
        'username': cfg.username,
        'password': password,
        'enabled': cfg.enabled,
        'updated_by': cfg.updated_by,
        'updated_at': cfg.updated_at.strftime('%Y-%m-%d %H:%M:%S') if cfg.updated_at else None,
    }

@settings_bp.route('/settings')
@login_required
def index():
    """Pagina de setări (doar admin)."""
    if not current_user.is_admin():
        flash('Acces interzis. Doar administratorii pot accesa setările.', 'danger')
        return redirect(url_for('dashboard.index'))

    from app.ids.sniffer import traffic_stats

    # Configurare Telegram
    telegram_enabled = _get_telegram_enabled()
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

    # Configurare MikroTik din BD (sau valori din env ca fallback)
    mikrotik_db_cfg = _get_mikrotik_config()
    if mikrotik_db_cfg is not None:
        mikrotik_config = {
            'host': mikrotik_db_cfg['host'],
            'port': mikrotik_db_cfg['port'],
            'username': mikrotik_db_cfg['username'],
            'enabled': mikrotik_db_cfg['enabled'],
            'updated_by': mikrotik_db_cfg['updated_by'],
            'updated_at': mikrotik_db_cfg['updated_at'],
            'source': 'database',
        }
    else:
        mikrotik_config = {
            'host': current_app.config.get('MIKROTIK_HOST', ''),
            'port': current_app.config.get('MIKROTIK_PORT', 8728),
            'username': current_app.config.get('MIKROTIK_USERNAME', 'admin'),
            'enabled': current_app.config.get('MIKROTIK_ENABLED', False),
            'updated_by': None,
            'updated_at': None,
            'source': 'env',
        }

    return render_template(
        'settings.html',
        telegram_enabled=telegram_enabled,
        chat_id_masked=chat_id_masked,
        whitelist_entries=whitelist_entries,
        system_info=system_info,
        mikrotik_config=mikrotik_config,
    )


@settings_bp.route('/api/settings/telegram/toggle', methods=['POST'])
@login_required
def toggle_telegram():
    """Activează sau dezactivează notificările Telegram în mod persistent."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis. Doar administratorii pot modifica setările.'}), 403

    token = current_app.config.get('TELEGRAM_BOT_TOKEN', '')
    chat_id = current_app.config.get('TELEGRAM_CHAT_ID', '')

    current_enabled = _get_telegram_enabled()
    new_enabled = not current_enabled

    # Validăm că token-ul și chat_id-ul sunt configurate înainte de activare
    if new_enabled and (not token or not chat_id):
        return jsonify({
            'error': 'TELEGRAM_BOT_TOKEN și TELEGRAM_CHAT_ID trebuie configurate înainte de activare.'
        }), 400

    _set_telegram_enabled(new_enabled)

    action_label = 'activate' if new_enabled else 'dezactivate'
    logger.info('[Settings] Notificările Telegram au fost %s de %s.', action_label, current_user.username)

    return jsonify({
        'success': True,
        'enabled': new_enabled,
        'message': f'Notificările Telegram au fost {"activate" if new_enabled else "dezactivate"}.'
    })


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


# =============================================================================
# API MikroTik Settings
# =============================================================================

@settings_bp.route('/api/settings/mikrotik', methods=['GET'])
@login_required
def get_mikrotik_config_api():
    """Returnează configurația MikroTik curentă (parola mascată)."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis.'}), 403

    from app.models import MikroTikConfig
    cfg = db.session.get(MikroTikConfig, 1)
    if cfg is None:
        # Fallback la variabilele de mediu
        return jsonify({
            'host': current_app.config.get('MIKROTIK_HOST', ''),
            'port': current_app.config.get('MIKROTIK_PORT', 8728),
            'username': current_app.config.get('MIKROTIK_USERNAME', 'admin'),
            'enabled': current_app.config.get('MIKROTIK_ENABLED', False),
            'updated_by': None,
            'updated_at': None,
            'source': 'env',
        })

    return jsonify({
        'host': cfg.host,
        'port': cfg.port,
        'username': cfg.username,
        'enabled': cfg.enabled,
        'updated_by': cfg.updated_by,
        'updated_at': cfg.updated_at.strftime('%Y-%m-%d %H:%M:%S') if cfg.updated_at else None,
        'source': 'database',
    })


@settings_bp.route('/api/settings/mikrotik', methods=['POST'])
@login_required
def save_mikrotik_config_api():
    """Salvează configurația MikroTik în baza de date (parola criptată)."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis.'}), 403

    data = request.get_json(silent=True) or {}

    host = data.get('host', '').strip()
    port_raw = data.get('port', 8728)
    username = data.get('username', '').strip()
    password = data.get('password', '')
    enabled = bool(data.get('enabled', False))

    # Validare
    if enabled and not host:
        return jsonify({'error': 'Host-ul este obligatoriu când integrarea MikroTik este activată.'}), 400
    try:
        port = int(port_raw)
        if not (1 <= port <= 65535):
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({'error': 'Portul trebuie să fie un număr între 1 și 65535.'}), 400

    from app.models import MikroTikConfig
    cfg = db.session.get(MikroTikConfig, 1)
    if cfg is None:
        cfg = MikroTikConfig(id=1)
        db.session.add(cfg)

    cfg.host = host
    cfg.port = port
    cfg.username = username or 'admin'
    cfg.enabled = enabled
    cfg.updated_by = current_user.username
    cfg.updated_at = datetime.now(timezone.utc)

    # Dacă o nouă parolă a fost trimisă, o criptăm; altfel păstrăm parola existentă
    if password:
        cfg.password_encrypted = _encrypt_password(password)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error('[MikroTik Settings] Eroare la salvarea configurației: %s', e)
        return jsonify({'error': 'Eroare la salvarea configurației în baza de date.'}), 500

    logger.info('[MikroTik Settings] Configurație salvată de %s (host=%s, enabled=%s).',
                current_user.username, host, enabled)

    # Reîncarcăm clientul MikroTik la runtime
    try:
        from app import reload_mikrotik_client
        reload_mikrotik_client(current_app._get_current_object())
    except Exception as e:
        logger.warning('[MikroTik Settings] Reîncărcare client eșuată: %s', e)

    return jsonify({
        'success': True,
        'message': 'Configurația MikroTik a fost salvată.',
        'enabled': enabled,
    })


@settings_bp.route('/api/settings/mikrotik/test', methods=['POST'])
@login_required
def test_mikrotik_connection():
    """Testează conexiunea MikroTik cu parametrii furnizați (sau cei salvați)."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis.'}), 403

    data = request.get_json(silent=True) or {}

    # Prioritate: parametri din request → config din BD → env
    host = data.get('host', '').strip()
    port_raw = data.get('port', '')
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not host:
        cfg = _get_mikrotik_config()
        if cfg:
            host = cfg['host']
            if not port_raw:
                port_raw = cfg['port']
            if not username:
                username = cfg['username']
            if not password:
                password = cfg['password']
        else:
            host = current_app.config.get('MIKROTIK_HOST', '')
            if not port_raw:
                port_raw = current_app.config.get('MIKROTIK_PORT', 8728)
            if not username:
                username = current_app.config.get('MIKROTIK_USERNAME', 'admin')
            if not password:
                password = current_app.config.get('MIKROTIK_PASSWORD', '')

    if not host:
        return jsonify({'error': 'Host-ul MikroTik nu este configurat.'}), 400

    try:
        port = int(port_raw) if port_raw else 8728
    except (TypeError, ValueError):
        port = 8728

    try:
        from app.ids.mikrotik_client import MikrotikClient
        test_client = MikrotikClient(
            host=host,
            port=port,
            username=username or 'admin',
            password=password,
        )
        connected = test_client.connect()
        if connected:
            test_client.disconnect()
            return jsonify({
                'success': True,
                'message': f'Conexiune reușită la {host}:{port}.',
            })
        return jsonify({'error': f'Nu s-a putut conecta la {host}:{port}. Verificați datele de acces.'}), 400
    except Exception as e:
        logger.warning('[MikroTik Settings] Test conexiune eșuat: %s', e)
        return jsonify({'error': f'Eroare la testarea conexiunii: {e}'}), 500


# =============================================================================
# API Service & System Management
# =============================================================================

def _log_service_action(event_type: str, message: str, ip: str):
    """Înregistrează o acțiune de serviciu/sistem în SecurityLog."""
    try:
        log = SecurityLog(
            event_type=event_type,
            source_ip=ip,
            message=message,
            severity='warning',
        )
        db.session.add(log)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.warning('[Service] Eroare la logarea acțiunii %s: %s', event_type, exc)


@settings_bp.route('/api/service/install', methods=['POST'])
@login_required
def service_install():
    """Instalează aplicația ca serviciu systemd."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis.'}), 403

    from app.utils import create_systemd_service
    success, message = create_systemd_service()
    ip = request.remote_addr or 'unknown'
    _log_service_action('service_installed', f'[{current_user.username}] {message}', ip)

    if success:
        return jsonify({'success': True, 'message': message})
    return jsonify({'error': message}), 500


@settings_bp.route('/api/service/restart', methods=['POST'])
@login_required
def service_restart():
    """Repornește serviciul systemd."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis.'}), 403

    from app.utils import manage_service
    success, message = manage_service('restart')
    ip = request.remote_addr or 'unknown'
    _log_service_action('service_restarted', f'[{current_user.username}] {message}', ip)

    if success:
        return jsonify({'success': True, 'message': message})
    return jsonify({'error': message}), 500


@settings_bp.route('/api/service/stop', methods=['POST'])
@login_required
def service_stop():
    """Oprește serviciul systemd."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis.'}), 403

    from app.utils import manage_service
    success, message = manage_service('stop')
    ip = request.remote_addr or 'unknown'
    _log_service_action('service_stopped', f'[{current_user.username}] {message}', ip)

    if success:
        return jsonify({'success': True, 'message': message})
    return jsonify({'error': message}), 500


@settings_bp.route('/api/service/status', methods=['GET'])
@login_required
def service_status():
    """Returnează statusul curent al serviciului systemd."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis.'}), 403

    from app.utils import get_service_status
    status = get_service_status()
    return jsonify(status)


@settings_bp.route('/api/service/logs', methods=['GET'])
@login_required
def service_logs():
    """Returnează ultimele 20 de linii din jurnalul serviciului."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis.'}), 403

    from app.utils import get_service_logs
    success, logs = get_service_logs(lines=20)
    if success:
        return jsonify({'success': True, 'logs': logs})
    return jsonify({'error': logs}), 500


@settings_bp.route('/api/system/restart-app', methods=['POST'])
@login_required
def system_restart_app():
    """Repornește procesul Flask (înlocuiește procesul curent cu os.execv)."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis.'}), 403

    import threading
    ip = request.remote_addr or 'unknown'
    _log_service_action('app_restarted', f'[{current_user.username}] Aplicația Flask a fost repornită.', ip)
    logger.warning('[System] Repornire aplicație Flask inițiată de %s.', current_user.username)

    def _do_restart():
        import time
        import os
        time.sleep(1)
        os.execv(sys.executable, [sys.executable] + sys.argv)

    t = threading.Thread(target=_do_restart, daemon=True)
    t.start()
    return jsonify({'success': True, 'message': 'Aplicația Flask va reporni în câteva secunde.'})


@settings_bp.route('/api/system/restart', methods=['POST'])
@login_required
def system_restart():
    """Repornește sistemul (reboot). Necesită confirmarea explicită în body."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis.'}), 403

    data = request.get_json(silent=True) or {}
    if not data.get('confirmed'):
        return jsonify({'error': 'Confirmarea este necesară pentru repornirea sistemului.'}), 400

    from app.utils import restart_system
    ip = request.remote_addr or 'unknown'
    _log_service_action('system_restarted', f'[{current_user.username}] Sistem restartat.', ip)

    success, message = restart_system()
    if success:
        return jsonify({'success': True, 'message': message})
    return jsonify({'error': message}), 500


@settings_bp.route('/api/system/uptime', methods=['GET'])
@login_required
def system_uptime():
    """Returnează uptime-ul sistemului și data ultimului boot."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis.'}), 403

    from app.utils import get_system_uptime
    return jsonify(get_system_uptime())

