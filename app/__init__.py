"""
Inițializarea aplicației Flask.
Folosim pattern-ul Application Factory pentru a crea instanța Flask.
"""
import os
from datetime import datetime, timezone, timedelta
from flask import Flask, request as flask_request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

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
    except Exception as e:
        print(f"[DB] Eroare la migrare automată: {e}")


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
    app.config.from_object(config[config_name])

    # Crearea directorului de loguri dacă nu există
    os.makedirs(app.config['LOG_DIR'], exist_ok=True)

    # Inițializarea extensiilor cu aplicația
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Trebuie să te autentifici pentru a accesa această pagină.'
    login_manager.login_message_category = 'warning'

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

    # Crearea tabelelor în baza de date dacă nu există
    with app.app_context():
        db.create_all()
        # Migrare automată: adaugă coloane noi în tabele existente
        _run_migrations(app)

    # Pornire integrare MikroTik (dacă este activată)
    if app.config.get('MIKROTIK_ENABLED'):
        from app.ids.mikrotik_client import MikrotikClient
        from app.ids.mikrotik_sync import start_mikrotik_sync
        mikrotik_client = MikrotikClient(
            host=app.config['MIKROTIK_HOST'],
            port=app.config['MIKROTIK_PORT'],
            username=app.config['MIKROTIK_USERNAME'],
            password=app.config['MIKROTIK_PASSWORD'],
        )
        mikrotik_client.connect()
        start_mikrotik_sync(app, mikrotik_client)
        app.mikrotik_client = mikrotik_client
        print(f"[MikroTik] Integrare activată pentru {app.config['MIKROTIK_HOST']}")

        # Monitorizare securitate externă
        if app.config.get('EXTERNAL_MONITOR_ENABLED', True):
            from app.ids.external_monitor import ExternalMonitor
            app._external_monitor = ExternalMonitor(app, mikrotik_client)
            print("[External Monitor] Monitorizare securitate externă activată.")

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

    return app
