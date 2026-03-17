"""
Rute pentru Setup Wizard (prima rulare).

Gestionează configurarea inițială a sistemului în 6 pași:
1. Configurare de bază (nume aplicație, admin, port, limbă)
2. Configurare rețea (mod sniffer, interfață, IP range)
3. Integrare MikroTik (opțional)
4. Setări securitate (SECRET_KEY, SSL/HTTPS)
5. Notificări Telegram (opțional)
6. Sumar & Inițializare (creare admin, pornire serviciu)
"""
import hashlib
import base64
import logging
import os
import secrets
import socket

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


@setup_bp.route('/api/setup/detect-interfaces', methods=['GET'])
def detect_interfaces():
    """Detectează automat interfețele de rețea disponibile pe sistem."""
    interfaces = []
    try:
        # Încercăm să obținem lista de interfețe folosind psutil
        try:
            import psutil
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        interfaces.append({'name': name, 'ip': addr.address})
                        break
        except ImportError:
            pass

        # Fallback: citim /proc/net/dev pe Linux
        if not interfaces:
            try:
                with open('/proc/net/dev', 'r') as f:
                    for line in f.readlines()[2:]:
                        name = line.split(':')[0].strip()
                        if name and name != 'lo':
                            interfaces.append({'name': name, 'ip': ''})
            except (OSError, IOError):
                pass

        # Fallback final: interfețe comune
        if not interfaces:
            for name in ['eth0', 'eth1', 'ens3', 'ens33', 'enp0s3', 'wlan0', 'wlan1']:
                interfaces.append({'name': name, 'ip': ''})

    except Exception as e:
        logger.warning('[Setup] Eroare la detectarea interfețelor: %s', e)

    return jsonify({'interfaces': interfaces})


@setup_bp.route('/api/setup/test-telegram', methods=['POST'])
def test_telegram():
    """Testează notificarea Telegram cu credențialele furnizate."""
    data = request.get_json(silent=True) or {}
    bot_token = data.get('bot_token', '').strip()
    chat_id = data.get('chat_id', '').strip()

    if not bot_token:
        return jsonify({'error': 'Token-ul bot-ului Telegram este obligatoriu.'}), 400
    if not chat_id:
        return jsonify({'error': 'Chat ID-ul Telegram este obligatoriu.'}), 400

    try:
        import requests as req_lib
        test_msg = '🔔 SchoolSec Setup: Test notificare Telegram reușit!'
        url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
        resp = req_lib.post(url, json={'chat_id': chat_id, 'text': test_msg}, timeout=10)
        if resp.status_code == 200 and resp.json().get('ok'):
            return jsonify({'success': True, 'message': 'Notificare Telegram trimisă cu succes!'})
        error_desc = resp.json().get('description', 'Eroare necunoscută.')
        return jsonify({'error': f'Eroare Telegram: {error_desc}'}), 400
    except Exception as e:
        logger.warning('[Setup] Test Telegram eșuat: %s', e)
        return jsonify({'error': f'Eroare la testarea Telegram: {e}'}), 500


@setup_bp.route('/api/setup/initialize', methods=['POST'])
def initialize():
    """Pasul final: inițializează tot sistemul cu configurația din wizard.

    Acțiuni:
    - Creează utilizatorul admin cu credențialele din Step 1
    - Persistă SECRET_KEY generat în fișierul .env
    - Salvează configurația rețelei (sniffer mode, interfață)
    - Salvează configurația MikroTik (dacă e activat)
    - Salvează configurația Telegram (dacă e activată)
    - Marchează setup_complete=true
    """
    data = request.get_json(silent=True) or {}

    # ─── Step 1: Basic Config ──────────────────────────────────────────────────
    admin_username = data.get('admin_username', 'admin').strip() or 'admin'
    app_name = data.get('app_name', 'SchoolSec').strip() or 'SchoolSec'
    app_port = data.get('app_port', 5000)

    # ─── Step 2: Network Config ────────────────────────────────────────────────
    sniffer_mode = data.get('sniffer_mode', 'simulated')
    network_interface = data.get('network_interface', '').strip()

    # ─── Step 3: MikroTik (opțional) ──────────────────────────────────────────
    mikrotik_enabled = data.get('mikrotik_enabled', False)
    mikrotik_host = data.get('mikrotik_host', '').strip()
    mikrotik_port = data.get('mikrotik_port', 8728)
    mikrotik_username = data.get('mikrotik_username', 'admin').strip() or 'admin'
    mikrotik_password = data.get('mikrotik_password', '')

    # ─── Step 4: Security ──────────────────────────────────────────────────────
    secret_key = data.get('secret_key', '').strip()
    if not secret_key:
        secret_key = secrets.token_hex(32)
    ssl_enabled = data.get('ssl_enabled', False)
    ssl_domain = data.get('ssl_domain', 'localhost').strip() or 'localhost'

    # ─── Step 5: Telegram (opțional) ──────────────────────────────────────────
    telegram_enabled = data.get('telegram_enabled', False)
    telegram_bot_token = data.get('telegram_bot_token', '').strip()
    telegram_chat_id = data.get('telegram_chat_id', '').strip()

    try:
        from app.models import User, SecurityLog

        # 1. Creare / actualizare utilizator admin
        admin_user = User.query.filter_by(username=admin_username).first()
        if admin_user is None:
            # Utilizatorul nu există – îl creăm cu parola implicită admin123
            admin_user = User(username=admin_username, email=f'{admin_username}@schoolsec.local', role='admin')
            admin_user.set_password('admin123')
            db.session.add(admin_user)
        else:
            admin_user.role = 'admin'
            # Nu modificăm parola existentă – utilizatorul o poate schimba din Setări

        # 2. Salvare configurație rețea în NetworkConfig
        def _set_config(key, value):
            row = NetworkConfig.query.filter_by(key=key).first()
            if row is None:
                row = NetworkConfig(key=key, value=str(value))
                db.session.add(row)
            else:
                row.value = str(value)

        _set_config('app_name', app_name)
        _set_config('app_port', str(app_port))
        _set_config('sniffer_mode', sniffer_mode)
        _set_config('network_interface', network_interface)
        _set_config('ssl_enabled', 'true' if ssl_enabled else 'false')
        _set_config('ssl_domain', ssl_domain)
        _set_config('telegram_enabled', 'true' if telegram_enabled else 'false')
        if telegram_enabled:
            _set_config('telegram_bot_token', telegram_bot_token)
            _set_config('telegram_chat_id', telegram_chat_id)

        # 3. Salvare configurație MikroTik
        if mikrotik_enabled and mikrotik_host:
            try:
                port_int = int(mikrotik_port)
                if not (1 <= port_int <= 65535):
                    raise ValueError
            except (TypeError, ValueError):
                port_int = 8728

            cfg = db.session.get(MikroTikConfig, 1)
            if cfg is None:
                cfg = MikroTikConfig(id=1)
                db.session.add(cfg)
            cfg.host = mikrotik_host
            cfg.port = port_int
            cfg.username = mikrotik_username
            cfg.enabled = True
            cfg.updated_by = 'setup_wizard'
            if mikrotik_password:
                fernet = _get_fernet()
                cfg.password_encrypted = fernet.encrypt(mikrotik_password.encode()).decode()
        else:
            # Dezactivăm MikroTik dacă era activat anterior
            cfg = db.session.get(MikroTikConfig, 1)
            if cfg is not None:
                cfg.enabled = False

        # 4. Marcare setup complet
        _set_config('setup_complete', 'true')

        # Log
        log_entry = SecurityLog(
            event_type='system_setup',
            message=f'Setup Wizard finalizat. Admin: {admin_username}, Sniffer: {sniffer_mode}.',
            severity='info'
        )
        db.session.add(log_entry)

        db.session.commit()
        logger.info('[Setup] Inițializare completă. Admin=%s, Sniffer=%s.', admin_username, sniffer_mode)

        # 5. Persistăm SECRET_KEY și setările cheie în .env (dacă e posibil)
        _persist_env_settings(secret_key, sniffer_mode, network_interface,
                              ssl_enabled, ssl_domain, app_port,
                              telegram_enabled, telegram_bot_token, telegram_chat_id)

        # 6. Reîncărcăm clientul MikroTik la runtime
        if mikrotik_enabled and mikrotik_host:
            try:
                from app import reload_mikrotik_client
                reload_mikrotik_client(current_app._get_current_object())
            except Exception as e:
                logger.warning('[Setup] Reîncărcare client MikroTik eșuată: %s', e)

        return jsonify({'success': True, 'redirect': url_for('auth.login')})

    except Exception as e:
        db.session.rollback()
        logger.error('[Setup] Eroare la inițializare: %s', e)
        return jsonify({'error': f'Eroare la inițializare: {e}'}), 500


def _persist_env_settings(secret_key, sniffer_mode, network_interface,
                          ssl_enabled, ssl_domain, app_port,
                          telegram_enabled, telegram_bot_token, telegram_chat_id):
    """Scrie setările cheie în fișierul .env din rădăcina proiectului.

    Dacă fișierul există, actualizează valorile existente; altfel creează unul nou.
    """
    try:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        env_path = os.path.join(base_dir, '.env')

        # Citim conținutul existent (dacă există)
        existing_lines = []
        if os.path.isfile(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                existing_lines = f.readlines()

        updates = {
            'SECRET_KEY': secret_key,
            'SNIFFER_MODE': sniffer_mode,
            'PORT': str(app_port),
        }
        if network_interface:
            updates['NETWORK_INTERFACE'] = network_interface
        if ssl_enabled:
            updates['SSL_CERT'] = f'{ssl_domain}.crt'
            updates['SSL_KEY'] = f'{ssl_domain}.key'
        if telegram_enabled and telegram_bot_token:
            updates['TELEGRAM_ENABLED'] = 'true'
            updates['TELEGRAM_BOT_TOKEN'] = telegram_bot_token
            if telegram_chat_id:
                updates['TELEGRAM_CHAT_ID'] = telegram_chat_id

        # Actualizăm liniile existente
        updated_keys = set()
        new_lines = []
        for line in existing_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or '=' not in stripped:
                new_lines.append(line)
                continue
            key = stripped.split('=', 1)[0].strip()
            if key in updates:
                new_lines.append(f'{key}={updates[key]}\n')
                updated_keys.add(key)
            else:
                new_lines.append(line)

        # Adăugăm cheile noi care nu existau
        for key, value in updates.items():
            if key not in updated_keys:
                new_lines.append(f'{key}={value}\n')

        with open(env_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

        logger.info('[Setup] Setări persistate în %s.', env_path)
    except Exception as e:
        # Nu blocăm setup-ul dacă nu putem scrie .env
        logger.warning('[Setup] Nu am putut persista setările în .env: %s', e)
