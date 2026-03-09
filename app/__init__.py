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

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(telegram_bp)
    app.register_blueprint(statistics_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(network_bp)

    # Crearea tabelelor în baza de date dacă nu există
    with app.app_context():
        db.create_all()
        # Migrare automată: adaugă coloane noi în tabele existente
        _run_migrations(app)

    @app.context_processor
    def inject_now():
        """Injectează data curentă în toate template-urile Jinja2."""
        return {'now': datetime.now(timezone.utc)}

    return app
