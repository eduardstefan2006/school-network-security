"""
Inițializarea aplicației Flask.
Folosim pattern-ul Application Factory pentru a crea instanța Flask.
"""
import os
from datetime import datetime, timezone
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

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


def _start_sniffer_once(app):
    """
    Pornește snifferul de rețea o singură dată, indiferent de cum e lansată aplicația
    (python run.py, Gunicorn, systemd, WSGI etc.).

    Evită pornirea dublă în modul debug Werkzeug (care fork-uiește procesul):
    - La primul fork (procesul parent), WERKZEUG_RUN_MAIN nu este setat → nu pornim
    - La al doilea fork (procesul child cu reloader), WERKZEUG_RUN_MAIN='true' → pornim
    - În producție (fără debug/reloader), pornim direct
    """
    from app.ids import sniffer as _sniffer_mod

    # Evităm pornirea dublă dacă snifferul rulează deja
    if _sniffer_mod._running:
        return

    # În modul debug Werkzeug cu reloader activ, așteptăm procesul child
    if app.debug and os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        return

    print("[SchoolSec] Pornire sniffer din create_app() (mod serviciu/Gunicorn compatibil)...")
    from app.ids.sniffer import start_sniffer
    start_sniffer(app)


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

    # Crearea tabelelor în baza de date dacă nu există
    with app.app_context():
        db.create_all()
        # Migrare automată: adaugă coloane noi în tabele existente
        _run_migrations(app)

    _start_sniffer_once(app)

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

    @app.context_processor
    def inject_now():
        """Injectează data curentă în toate template-urile Jinja2."""
        return {'now': datetime.now(timezone.utc)}

    return app
