"""
Funcții utilitare pentru validare și alte operații comune.
"""
import re
import os
import sys
import time
import subprocess
import logging
from datetime import datetime, timezone
from functools import wraps

from flask import request
from flask_login import current_user
from markupsafe import escape

logger = logging.getLogger(__name__)

# Lungimea minimă acceptată pentru parole
MIN_PASSWORD_LENGTH = 8

# Lungimea minimă/maximă acceptată pentru username-uri
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 20

# Pattern pentru username valid: litere, cifre, underscore, cratimă
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_-]+$')

# Numele serviciului systemd
SERVICE_NAME = 'schoolsec'


def validate_username(username: str):
    """Validează formatul unui username.

    Cerințe:
      - Minim 3 caractere, maxim 20
      - Numai litere (a-z, A-Z), cifre (0-9), underscore (_) sau cratimă (-)
      - Protecție anti-XSS prin escapare HTML

    Returnează (True, username_escaped) dacă valid sau
    (False, mesaj_eroare) dacă nu îndeplinește cerințele.
    """
    if not username:
        return False, 'Numele de utilizator este obligatoriu.'
    if len(username) < MIN_USERNAME_LENGTH or len(username) > MAX_USERNAME_LENGTH:
        return False, (
            f'Numele de utilizator trebuie să aibă între '
            f'{MIN_USERNAME_LENGTH} și {MAX_USERNAME_LENGTH} caractere.'
        )
    if not _USERNAME_RE.match(username):
        return False, 'Numele de utilizator poate conține numai litere, cifre, _ sau -.'
    return True, str(escape(username))


def validate_password(password):
    """
    Validează complexitatea parolei.

    Cerințe:
      - Minim 8 caractere
      - Cel puțin o literă mare
      - Cel puțin o literă mică
      - Cel puțin o cifră

    Returnează (True, '') dacă parola este validă sau
    (False, mesaj_eroare) dacă nu îndeplinește cerințele.
    """
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False, f'Parola trebuie să aibă cel puțin {MIN_PASSWORD_LENGTH} caractere.'
    if not re.search(r'[A-Z]', password):
        return False, 'Parola trebuie să conțină cel puțin o literă mare.'
    if not re.search(r'[a-z]', password):
        return False, 'Parola trebuie să conțină cel puțin o literă mică.'
    if not re.search(r'\d', password):
        return False, 'Parola trebuie să conțină cel puțin o cifră.'
    return True, ''


def audit_log(event_type: str, severity: str = 'info'):
    """Decorator care înregistrează automat acțiunile administrative în SecurityLog.

    Evenimentul se înregistrează numai pentru request-uri de scriere (POST, PUT, DELETE, PATCH),
    nu și pentru GET-uri.

    Utilizare::

        @admin_bp.route('/delete-user/<int:id>', methods=['POST'])
        @audit_log('user_deleted', 'critical')
        def delete_user(id):
            ...

    :param event_type: Tipul evenimentului (ex: 'user_deleted', 'config_changed').
    :param severity: Severitatea log-ului: 'info', 'warning', 'error', 'critical'.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Înregistrăm doar acțiunile de scriere, nu request-urile GET
            if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
                from app import db
                from app.models import SecurityLog
                try:
                    user_id = current_user.id if current_user.is_authenticated else None
                    username = current_user.username if current_user.is_authenticated else 'system'
                    log = SecurityLog(
                        event_type=event_type,
                        user_id=user_id,
                        source_ip=request.remote_addr,
                        message=f'Acțiune: {event_type} executată de {username}',
                        severity=severity,
                    )
                    db.session.add(log)
                    db.session.commit()
                except Exception as exc:
                    logger.warning('[AuditLog] Eroare la înregistrarea acțiunii %s: %s', event_type, exc)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# =============================================================================
# Utilitare gestionare serviciu systemd și sistem
# =============================================================================

def create_systemd_service():
    """Creează și instalează fișierul de serviciu systemd pentru SchoolSec.

    Generează /etc/systemd/system/schoolsec.service cu calea corectă
    a interpretorului Python și a directorului de lucru.
    Necesită privilegii root (sudo).

    Returnează (True, mesaj) la succes sau (False, mesaj_eroare) la eșec.
    """
    try:
        # Calea absolută a directorului proiectului (două niveluri deasupra utils.py)
        project_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        python_exec = sys.executable
        run_script = os.path.join(project_dir, 'run.py')

        service_content = f"""[Unit]
Description=SchoolSec - School Network Security Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={project_dir}
ExecStart={python_exec} {run_script}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier={SERVICE_NAME}

[Install]
WantedBy=multi-user.target
"""
        service_path = f'/etc/systemd/system/{SERVICE_NAME}.service'

        # Scriem fișierul de serviciu (necesită sudo)
        write_result = subprocess.run(
            ['sudo', 'tee', service_path],
            input=service_content,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if write_result.returncode != 0:
            return False, f'Eroare la scrierea fișierului de serviciu: {write_result.stderr.strip()}'

        # Reîncarcăm systemd și activăm serviciul
        for cmd in [
            ['sudo', 'systemctl', 'daemon-reload'],
            ['sudo', 'systemctl', 'enable', SERVICE_NAME],
        ]:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                return False, f'Eroare la comanda {" ".join(cmd)}: {result.stderr.strip()}'

        logger.info('[Service] Serviciul %s a fost instalat cu succes.', SERVICE_NAME)
        return True, f'Serviciul {SERVICE_NAME} a fost instalat și activat.'
    except FileNotFoundError:
        return False, 'sudo sau systemctl nu sunt disponibile pe acest sistem.'
    except subprocess.TimeoutExpired:
        return False, 'Timeout la instalarea serviciului.'
    except Exception as e:
        logger.error('[Service] Eroare la instalarea serviciului: %s', e)
        return False, f'Eroare neașteptată: {e}'


def manage_service(action: str):
    """Pornește, oprește sau repornește serviciul systemd SchoolSec.

    :param action: 'start' | 'stop' | 'restart'
    Returnează (True, mesaj) la succes sau (False, mesaj_eroare) la eșec.
    """
    if action not in ('start', 'stop', 'restart'):
        return False, f'Acțiune invalidă: {action}'
    try:
        result = subprocess.run(
            ['sudo', 'systemctl', action, SERVICE_NAME],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            logger.info('[Service] Acțiunea "%s" a fost executată pe serviciul %s.', action, SERVICE_NAME)
            return True, f'Acțiunea "{action}" a fost executată cu succes pe serviciul {SERVICE_NAME}.'
        return False, result.stderr.strip() or result.stdout.strip() or f'Eroare la acțiunea {action}.'
    except FileNotFoundError:
        return False, 'sudo sau systemctl nu sunt disponibile pe acest sistem.'
    except subprocess.TimeoutExpired:
        return False, f'Timeout la acțiunea {action}.'
    except Exception as e:
        logger.error('[Service] Eroare la acțiunea %s: %s', action, e)
        return False, f'Eroare neașteptată: {e}'


def get_service_status():
    """Verifică dacă serviciul systemd SchoolSec este activ.

    Returnează un dict cu cheile: active (bool), status (str), description (str).
    """
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', SERVICE_NAME],
            capture_output=True, text=True, timeout=10,
        )
        active_state = result.stdout.strip()
        is_active = active_state == 'active'

        # Obținem și descrierea detaliată
        status_result = subprocess.run(
            ['systemctl', 'status', SERVICE_NAME, '--no-pager', '-l'],
            capture_output=True, text=True, timeout=10,
        )
        description = status_result.stdout.strip() if status_result.returncode in (0, 3) else ''

        return {
            'active': is_active,
            'status': active_state,
            'description': description,
        }
    except FileNotFoundError:
        return {'active': False, 'status': 'unavailable', 'description': 'systemctl nu este disponibil.'}
    except subprocess.TimeoutExpired:
        return {'active': False, 'status': 'timeout', 'description': 'Timeout la verificarea statusului.'}
    except Exception as e:
        logger.error('[Service] Eroare la verificarea statusului: %s', e)
        return {'active': False, 'status': 'error', 'description': str(e)}


def get_service_logs(lines: int = 20):
    """Returnează ultimele ``lines`` linii din jurnalul systemd al serviciului.

    Returnează (True, text_log) sau (False, mesaj_eroare).
    """
    try:
        result = subprocess.run(
            ['journalctl', '-u', SERVICE_NAME, '--no-pager', '-n', str(lines), '--output=short-iso'],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            return True, result.stdout or '(nicio intrare în jurnal)'
        # journalctl poate returna cod 1 dacă unitatea nu există
        return False, result.stderr.strip() or 'Nu s-au putut obține log-urile.'
    except FileNotFoundError:
        return False, 'journalctl nu este disponibil pe acest sistem.'
    except subprocess.TimeoutExpired:
        return False, 'Timeout la obținerea log-urilor.'
    except Exception as e:
        logger.error('[Service] Eroare la obținerea log-urilor: %s', e)
        return False, f'Eroare neașteptată: {e}'


def get_system_uptime():
    """Returnează uptime-ul sistemului ca string lizibil.

    Returnează un dict cu cheile: uptime_str (str), boot_time (str).
    """
    try:
        # /proc/uptime conține secunde de la boot
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.read().split()[0])

        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        seconds = int(uptime_seconds % 60)

        parts = []
        if days:
            parts.append(f'{days}z')
        if hours:
            parts.append(f'{hours}h')
        if minutes:
            parts.append(f'{minutes}m')
        parts.append(f'{seconds}s')
        uptime_str = ' '.join(parts)

        # Calculăm timpul de boot
        boot_timestamp = time.time() - uptime_seconds
        boot_time = datetime.fromtimestamp(boot_timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        return {'uptime_str': uptime_str, 'boot_time': boot_time}
    except Exception as e:
        logger.warning('[System] Eroare la citirea uptime-ului: %s', e)
        return {'uptime_str': 'N/A', 'boot_time': 'N/A'}


def restart_system():
    """Inițiază rebooting-ul sistemului.

    Returnează (True, mesaj) la succes sau (False, mesaj_eroare) la eșec.
    ATENȚIE: operație distructivă – necesită confirmare înainte de apel.
    """
    try:
        result = subprocess.run(
            ['sudo', 'shutdown', '-r', 'now'],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            logger.warning('[System] Sistem restartat de administrator.')
            return True, 'Sistemul va reporni în câteva secunde.'
        return False, result.stderr.strip() or 'Eroare la repornirea sistemului.'
    except FileNotFoundError:
        return False, 'sudo sau shutdown nu sunt disponibile pe acest sistem.'
    except subprocess.TimeoutExpired:
        return False, 'Timeout la repornirea sistemului.'
    except Exception as e:
        logger.error('[System] Eroare la repornirea sistemului: %s', e)
        return False, f'Eroare neașteptată: {e}'
