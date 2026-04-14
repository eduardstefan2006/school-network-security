"""
Inițializarea aplicației Flask.
Folosim pattern-ul Application Factory pentru a crea instanța Flask.
"""
import os
from datetime import datetime, timezone, timedelta
from flask import Flask, request as flask_request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

try:
    from zoneinfo import ZoneInfo
    _LOCAL_TZ = ZoneInfo('Europe/Bucharest')
except ImportError:
    # Fallback pentru Python < 3.9: offset fix UTC+2 (fără DST).
    # Notă: nu reflectă ora de vară (UTC+3) — folosiți Python 3.9+ cu zoneinfo.
    _LOCAL_TZ = timezone(timedelta(hours=2))

# Instanțele extensiilor (fără a fi legate de aplicație)
db = SQLAlchemy()
login_manager = LoginManager()
# Rate limiter: protecție anti brute-force (implicit 200/zi, 50/oră)
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
# Protecție CSRF pentru toate formularele POST
csrf = CSRFProtect()


def _run_migrations(app):
    """Adaugă coloane noi în tabele existente (migrare automată la pornire)."""
    try:
        from sqlalchemy import text
        with db.engine.connect() as conn:
            # Verificăm și adăugăm coloana hostname în network_devices
            result = conn.execute(text("PRAGMA table_info(network_devices)"))
            existing_cols = [row[1] for row in result]

            if 'hostname' not in existing_cols:
                conn.execute(text(
                    "ALTER TABLE network_devices ADD COLUMN hostname VARCHAR(255)"
                ))
                conn.commit()
                print("[DB] Migrare: coloana 'hostname' adăugată în network_devices.")

            if 'type_locked' not in existing_cols:
                conn.execute(text(
                    "ALTER TABLE network_devices ADD COLUMN type_locked BOOLEAN DEFAULT 0"
                ))
                conn.commit()
                print("[DB] Migrare: coloana 'type_locked' adăugată în network_devices.")

            # Verificăm și adăugăm coloana user_id în security_logs
            result = conn.execute(text("PRAGMA table_info(security_logs)"))
            log_cols = [row[1] for row in result]
            if 'user_id' not in log_cols:
                conn.execute(text(
                    "ALTER TABLE security_logs ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL"
                ))
                conn.commit()
                print("[DB] Migrare: coloana 'user_id' adăugată în security_logs.")

            # Migrare câmpuri ML în tabela alerts
            result = conn.execute(text("PRAGMA table_info(alerts)"))
            alert_cols = [row[1] for row in result]
            if 'anomaly_score' not in alert_cols:
                conn.execute(text(
                    "ALTER TABLE alerts ADD COLUMN anomaly_score FLOAT DEFAULT NULL"
                ))
                conn.commit()
                print("[DB] Migrare: coloana 'anomaly_score' adăugată în alerts.")
            if 'model_confidence' not in alert_cols:
                conn.execute(text(
                    "ALTER TABLE alerts ADD COLUMN model_confidence FLOAT DEFAULT NULL"
                ))
                conn.commit()
                print("[DB] Migrare: coloana 'model_confidence' adăugată în alerts.")
            if 'is_ml_generated' not in alert_cols:
                conn.execute(text(
                    "ALTER TABLE alerts ADD COLUMN is_ml_generated BOOLEAN DEFAULT 0"
                ))
                conn.commit()
                print("[DB] Migrare: coloana 'is_ml_generated' adăugată în alerts.")

            # Migrare Faza 3: tabele noi create prin db.create_all() la pornire.
            # Verificăm că tabelele există (create_all le creează automat dacă lipsesc).
            # Nicio coloană suplimentară nu trebuie adăugată manual.
    except Exception as e:
        print(f"[DB] Eroare la migrare automată: {e}")


def _load_mikrotik_params(app):
    """Returnează parametrii MikroTik (enabled, host, port, username, password).

    Prioritate: înregistrare din baza de date → variabile de mediu (.env).
    """
    try:
        from app.models import MikroTikConfig
        import hashlib
        import base64
        from cryptography.fernet import Fernet

        with app.app_context():
            cfg = db.session.get(MikroTikConfig, 1)

        if cfg is not None:
            password = ''
            if cfg.password_encrypted:
                try:
                    secret = app.config['SECRET_KEY'].encode()
                    fernet_key = base64.urlsafe_b64encode(hashlib.sha256(secret).digest())
                    password = Fernet(fernet_key).decrypt(cfg.password_encrypted.encode()).decode()
                except Exception as e:
                    print(f"[MikroTik] Eroare la decriptarea parolei din BD: {e}")
            return {
                'enabled': cfg.enabled,
                'host': cfg.host,
                'port': cfg.port,
                'username': cfg.username,
                'password': password,
                'source': 'database',
            }
    except Exception as e:
        print(f"[MikroTik] Fallback la .env (eroare BD: {e})")

    # Fallback la .env
    return {
        'enabled': app.config.get('MIKROTIK_ENABLED', False),
        'host': app.config.get('MIKROTIK_HOST', ''),
        'port': app.config.get('MIKROTIK_PORT', 8728),
        'username': app.config.get('MIKROTIK_USERNAME', 'admin'),
        'password': app.config.get('MIKROTIK_PASSWORD', ''),
        'source': 'env',
    }


def _init_mikrotik(app):
    """Inițializează clientul MikroTik și serviciile asociate."""
    params = _load_mikrotik_params(app)
    if not params['enabled']:
        return

    from app.ids.mikrotik_client import MikrotikClient
    from app.ids.mikrotik_sync import start_mikrotik_sync

    mikrotik_client = MikrotikClient(
        host=params['host'],
        port=params['port'],
        username=params['username'],
        password=params['password'],
    )
    mikrotik_client.connect()
    start_mikrotik_sync(app, mikrotik_client)
    app.mikrotik_client = mikrotik_client
    print(f"[MikroTik] Integrare activată pentru {params['host']} (sursă: {params['source']})")

    # Monitorizare securitate externă
    if app.config.get('EXTERNAL_MONITOR_ENABLED', True):
        from app.ids.external_monitor import ExternalMonitor
        app._external_monitor = ExternalMonitor(app, mikrotik_client)
        print("[External Monitor] Monitorizare securitate externă activată.")


def reload_mikrotik_client(app):
    """Reîncarcă clientul MikroTik la runtime după modificarea configurației.

    Deconectează clientul existent, creează unul nou cu parametrii actualizați
    și pornește un nou thread de sincronizare.
    """
    # Deconectăm clientul existent (dacă există)
    old_client = getattr(app, 'mikrotik_client', None)
    if old_client is not None:
        try:
            old_client.disconnect()
        except Exception:
            pass
        app.mikrotik_client = None

    params = _load_mikrotik_params(app)
    if not params['enabled']:
        print("[MikroTik] Integrare dezactivată – clientul nu a fost reîncărcat.")
        return

    from app.ids.mikrotik_client import MikrotikClient
    from app.ids.mikrotik_sync import start_mikrotik_sync

    new_client = MikrotikClient(
        host=params['host'],
        port=params['port'],
        username=params['username'],
        password=params['password'],
    )
    new_client.connect()
    start_mikrotik_sync(app, new_client)
    app.mikrotik_client = new_client
    print(f"[MikroTik] Client reîncărcat pentru {params['host']} (sursă: {params['source']})")



def _ensure_admin_user():
    """Creează utilizatorul admin implicit dacă nu există în baza de date.

    La prima rulare, aplicația va crea automat utilizatorul 'admin' cu parola
    'Admin123'. Aceasta poate fi schimbată din pagina de Setări după autentificare.
    """
    try:
        from app.models import User
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@schoolsec.local', role='admin')
            admin.set_password('Admin123')
            db.session.add(admin)
            db.session.commit()
            print('[DB] Utilizator admin creat cu credențiale implicite.')
    except Exception as e:
        print(f'[DB] Eroare la crearea utilizatorului admin implicit: {e}')


def _init_infrastructure_whitelist():
    """Inițializează lista albă de infrastructură cu intrările implicite la prima rulare."""
    try:
        from app.models import InfrastructureWhitelist
        from config import DEFAULT_INFRASTRUCTURE_WHITELIST
        if InfrastructureWhitelist.query.count() == 0:
            for entry_data in DEFAULT_INFRASTRUCTURE_WHITELIST:
                entry = InfrastructureWhitelist(
                    ip_address=entry_data['ip_address'],
                    hostname=entry_data.get('hostname'),
                    service_type=entry_data['service_type'],
                    description=entry_data.get('description'),
                )
                db.session.add(entry)
            db.session.commit()
            print('[DB] Listă albă infrastructură inițializată cu intrările implicite.')
    except Exception as e:
        print(f'[DB] Eroare la inițializarea listei albe de infrastructură: {e}')


def _init_background_jobs(app):
    """Inițializează job-urile de fundal (scheduler APScheduler)."""
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from app.monitoring.disk_monitor import disk_monitor

        scheduler = BackgroundScheduler()

        # Verifică discul la fiecare 5 minute
        scheduler.add_job(
            func=lambda: disk_monitor.check_and_alert(),
            trigger='interval',
            minutes=5,
            id='disk_monitor',
            name='Disk Monitor',
        )

        scheduler.start()
        print('[Scheduler] Job de monitorizare disc pornit (interval: 5 min).')
    except ImportError:
        print('[Scheduler] APScheduler nu este instalat – monitorizarea discului nu rulează automat.')
    except Exception as e:
        print(f'[Scheduler] Eroare la pornirea scheduler-ului: {e}')


def create_app(config_name=None):
    """
    Factory function pentru crearea aplicației Flask.
    Permite crearea mai multor instanțe cu configurări diferite.
    """
    app = Flask(__name__)

    # Încărcarea configurației
    from config import config
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'default')
    config_class = config[config_name]
    app.config.from_object(config_class)
    # Hook opțional de inițializare/validare specific mediului
    if hasattr(config_class, 'init_app'):
        config_class.init_app(app)

    # Crearea directorului de loguri dacă nu există
    os.makedirs(app.config['LOG_DIR'], exist_ok=True)

    # Inițializarea extensiilor cu aplicația
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Trebuie să te autentifici pentru a accesa această pagină.'
    login_manager.login_message_category = 'warning'
    # Inițializare rate limiter (anti brute-force)
    limiter.init_app(app)
    # Inițializare protecție CSRF pentru toate formularele
    csrf.init_app(app)

    # Înregistrarea blueprint-urilor (modulelor de rute)
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.alerts import alerts_bp
    from app.routes.users import users_bp
    from app.routes.telegram import telegram_bp
    from app.routes.statistics import statistics_bp
    from app.routes.settings import settings_bp
    from app.routes.reports import reports_bp
    from app.routes.network import network_bp
    from app.routes.mikrotik import mikrotik_bp
    from app.routes.external import external_bp
    from app.routes.setup import setup_bp
    from app.routes.response import response_bp
    from app.routes.monitoring import monitoring_bp
    from app.routes.infrastructure import infrastructure_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(telegram_bp)
    app.register_blueprint(statistics_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(network_bp)
    app.register_blueprint(mikrotik_bp)
    app.register_blueprint(external_bp)
    app.register_blueprint(setup_bp)
    app.register_blueprint(response_bp)
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(infrastructure_bp)

    # Crearea tabelelor în baza de date dacă nu există
    with app.app_context():
        db.create_all()
        # Migrare automată: adaugă coloane noi în tabele existente
        _run_migrations(app)
        # Creare automată utilizator admin implicit la prima rulare
        _ensure_admin_user()
        # Inițializare listă albă infrastructură implicită (la prima rulare)
        _init_infrastructure_whitelist()

    # Pornire integrare MikroTik – prioritate: config din BD, fallback la .env
    _init_mikrotik(app)

    # Pornire server syslog UDP – primește log-uri firewall de la RouterOS
    from app.ids.syslog_server import start_syslog_server
    start_syslog_server(app)

    # Pornire thread ML de antrenare (detectare anomalii bazată pe ML)
    if app.config.get('ML_ENABLED', True):
        from app.ml.trainer import start_ml_trainer
        retrain_hours = app.config.get('ML_MODEL_RETRAIN_HOURS', 24)
        start_ml_trainer(app, retrain_interval=retrain_hours * 3600)

    # Inițializare modul de monitorizare disc
    from app.monitoring.disk_monitor import disk_monitor
    disk_monitor.init_app(app)
    _init_background_jobs(app)

    @app.template_filter('to_local')
    def to_local_filter(dt):
        """Convertește un datetime UTC la ora locală a României."""
        if dt is None:
            return ''
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(_LOCAL_TZ)

    @app.context_processor
    def inject_now():
        """Injectează data curentă (ora României) în toate template-urile Jinja2."""
        return {'now': datetime.now(timezone.utc).astimezone(_LOCAL_TZ)}

    @app.before_request
    def check_first_run():
        """Redirecționează la Setup Wizard dacă setup-ul inițial nu a fost finalizat.

        Excepții: rutele setup.*, auth.*, static și request-urile API ale setup-ului.
        """
        from flask import redirect, url_for
        # Permitem accesul liber la rute de setup, auth și fișiere statice
        if flask_request.endpoint is None:
            return
        if flask_request.endpoint.startswith(('setup.', 'auth.', 'static')):
            return
        try:
            from app.models import NetworkConfig
            cfg = NetworkConfig.query.filter_by(key='setup_complete').first()
            if cfg is None or cfg.value != 'true':
                return redirect(url_for('setup.index'))
        except Exception:
            # Dacă BD nu e disponibilă, permitem accesul (nu blocăm la pornire)
            pass

    @app.after_request
    def add_security_headers(response):
        """Adaugă headers HTTP de securitate la fiecare răspuns."""
        # HSTS: forțează HTTPS — se trimite doar dacă cererea curentă e securizată
        if flask_request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        # Previne MIME-type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # Previne afișarea în iframe (clickjacking)
        response.headers['X-Frame-Options'] = 'DENY'
        # Politică de referrer minimă
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # Dezactivează cache-ul pentru răspunsuri HTML (pagini cu date sensibile)
        content_type = response.content_type or ''
        if 'text/html' in content_type:
            response.headers['Cache-Control'] = 'no-store'
        # Politică de conținut: permite resurse proprii + CDN-uri utilizate de Bootstrap/Chart.js
        # 'unsafe-inline' este necesar deoarece template-urile existente folosesc scripturi și
        # stiluri inline; în viitor acestea pot fi mutate în fișiere externe.
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        return response

    @app.errorhandler(429)
    def ratelimit_error(e):
        """Răspuns pentru depășirea limitei de rată (rate limiting)."""
        from flask import jsonify, render_template as _render
        retry_after = getattr(e, 'retry_after', 60)
        if flask_request.accept_mimetypes.accept_json and \
                not flask_request.accept_mimetypes.accept_html:
            return jsonify(error='Prea multe cereri. Încercați din nou mai târziu.',
                           retry_after=retry_after), 429
        return _render('login.html', rate_limit_error=True, retry_after=retry_after), 429

    return app
