"""
Rute pentru Setup Wizard (prima rulare).

Gestionează configurarea inițială a sistemului:
1. Introducerea credențialelor MikroTik
2. Testarea conexiunii la RouterOS
3. Pornirea auto-discovery
4. Finalizarea setup-ului
"""
import hashlib
import base64
import logging

from flask import Blueprint, render_template, redirect, url_for, jsonify, request, current_app
from flask_login import login_required, current_user

from app import db
from app.models import NetworkConfig, MikroTikConfig

setup_bp = Blueprint('setup', __name__)
logger = logging.getLogger(__name__)


def is_setup_complete() -> bool:
    """Returnează True dacă setup-ul inițial a fost finalizat."""
    try:
        cfg = NetworkConfig.query.filter_by(key='setup_complete').first()
        return cfg is not None and cfg.value == 'true'
    except Exception:
        return False


def _get_fernet():
    """Returnează o instanță Fernet cu cheia derivată din SECRET_KEY."""
    from cryptography.fernet import Fernet
    secret = current_app.config['SECRET_KEY'].encode()
    key_bytes = hashlib.sha256(secret).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(fernet_key)


@setup_bp.route('/setup')
def index():
    """Pagina Setup Wizard."""
    if is_setup_complete():
        return redirect(url_for('dashboard.index'))
    return render_template('setup.html')


@setup_bp.route('/api/setup/test-connection', methods=['POST'])
def test_connection():
    """Testează conexiunea la RouterOS cu credențialele furnizate."""
    data = request.get_json(silent=True) or {}

    host = data.get('host', '').strip()
    port_raw = data.get('port', 8728)
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not host:
        return jsonify({'error': 'Adresa IP a routerului este obligatorie.'}), 400

    try:
        port = int(port_raw)
        if not (1 <= port <= 65535):
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({'error': 'Portul trebuie să fie un număr între 1 și 65535.'}), 400

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
            # Obținem identitatea routerului pentru confirmare
            identity = test_client.get_router_identity()
            test_client.disconnect()
            return jsonify({
                'success': True,
                'message': f'Conexiune reușită la {host}:{port}.',
                'router_identity': identity,
            })
        return jsonify({'error': f'Nu s-a putut conecta la {host}:{port}. Verificați datele de acces.'}), 400
    except Exception as e:
        logger.warning('[Setup] Test conexiune eșuat: %s', e)
        return jsonify({'error': f'Eroare la testarea conexiunii: {e}'}), 500


@setup_bp.route('/api/setup/save-config', methods=['POST'])
def save_config():
    """Salvează configurația MikroTik și pornește auto-discovery."""
    data = request.get_json(silent=True) or {}

    host = data.get('host', '').strip()
    port_raw = data.get('port', 8728)
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not host:
        return jsonify({'error': 'Adresa IP a routerului este obligatorie.'}), 400

    try:
        port = int(port_raw)
        if not (1 <= port <= 65535):
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({'error': 'Portul trebuie să fie un număr între 1 și 65535.'}), 400

    try:
        cfg = db.session.get(MikroTikConfig, 1)
        if cfg is None:
            cfg = MikroTikConfig(id=1)
            db.session.add(cfg)

        cfg.host = host
        cfg.port = port
        cfg.username = username or 'admin'
        cfg.enabled = True
        cfg.updated_by = 'setup_wizard'

        if password:
            cfg.password_encrypted = _get_fernet().encrypt(password.encode()).decode()

        db.session.commit()
        logger.info('[Setup] Configurație MikroTik salvată (host=%s).', host)
    except Exception as e:
        db.session.rollback()
        logger.error('[Setup] Eroare la salvarea configurației: %s', e)
        return jsonify({'error': f'Eroare la salvarea configurației: {e}'}), 500

    # Reîncărcăm clientul MikroTik
    try:
        from app import reload_mikrotik_client
        reload_mikrotik_client(current_app._get_current_object())
    except Exception as e:
        logger.warning('[Setup] Reîncărcare client eșuată: %s', e)

    return jsonify({'success': True, 'message': 'Configurație salvată.'})


@setup_bp.route('/api/setup/start-discovery', methods=['POST'])
def start_discovery():
    """Pornește procesul de auto-discovery în background."""
    mikrotik_client = getattr(current_app, 'mikrotik_client', None)
    if mikrotik_client is None or not mikrotik_client.is_connected():
        # Încercăm să conectăm pe baza config-ului salvat
        try:
            from app import reload_mikrotik_client
            reload_mikrotik_client(current_app._get_current_object())
            mikrotik_client = getattr(current_app, 'mikrotik_client', None)
        except Exception as e:
            logger.warning('[Setup] Reconectare MikroTik eșuată: %s', e)

    if mikrotik_client is None or not mikrotik_client.is_connected():
        return jsonify({'error': 'Clientul MikroTik nu este conectat. Salvați mai întâi configurația.'}), 400

    try:
        from app.services.auto_discovery import start_discovery_async, get_discovery_state
        state = get_discovery_state()
        if state['running']:
            return jsonify({'message': 'Auto-discovery rulează deja.', 'state': state})

        start_discovery_async(current_app._get_current_object(), mikrotik_client)
        return jsonify({'success': True, 'message': 'Auto-discovery pornit.'})
    except Exception as e:
        logger.error('[Setup] Eroare la pornirea auto-discovery: %s', e)
        return jsonify({'error': f'Eroare la pornirea auto-discovery: {e}'}), 500


@setup_bp.route('/api/setup/discovery-status', methods=['GET'])
def discovery_status():
    """Returnează starea curentă a procesului de auto-discovery."""
    try:
        from app.services.auto_discovery import get_discovery_state
        state = get_discovery_state()
        return jsonify(state)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@setup_bp.route('/api/setup/skip', methods=['POST'])
def skip_setup():
    """Marchează setup-ul ca finalizat fără auto-discovery (modul demo/test)."""
    try:
        cfg = NetworkConfig.query.filter_by(key='setup_complete').first()
        if cfg is None:
            cfg = NetworkConfig(key='setup_complete', value='true')
            db.session.add(cfg)
        else:
            cfg.value = 'true'
        db.session.commit()
        logger.info('[Setup] Setup marcat ca finalizat (skip).')
        return jsonify({'success': True, 'redirect': url_for('dashboard.index')})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
