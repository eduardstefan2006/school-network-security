"""
Configurarea aplicației Flask pentru sistemul de securitate al rețelei școlare.
"""
import os

# Directorul de bază al proiectului
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

_DEFAULT_SECRET_KEY = 'school-security-secret-key-2024'


class Config:
    """Configurare de bază."""
    # Cheie secretă pentru sesiuni Flask
    # IMPORTANT: Setați variabila de mediu SECRET_KEY în producție!
    SECRET_KEY = os.environ.get('SECRET_KEY') or _DEFAULT_SECRET_KEY

    # Setări cookie sesiune securizate
    SESSION_COOKIE_HTTPONLY = True   # Cookie-ul de sesiune nu e accesibil din JavaScript
    SESSION_COOKIE_SAMESITE = 'Lax'  # Protecție CSRF de bază

    # Protecție CSRF (Flask-WTF)
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # Token CSRF expiră după 1 oră

    # Calea spre fișierele certificat SSL/TLS (opțional, pentru HTTPS)
    SSL_CERT = os.environ.get('SSL_CERT', '')   # ex: cert.pem
    SSL_KEY = os.environ.get('SSL_KEY', '')     # ex: key.pem

    # Baza de date SQLite
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(BASE_DIR, 'security.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Directorul pentru loguri
    LOG_DIR = os.path.join(BASE_DIR, 'logs')

    # Setări IDS (Intrusion Detection System)
    # Numărul de porturi scanate în intervalul de timp pentru a declanșa alerta de port scan
    PORT_SCAN_THRESHOLD = 15
    PORT_SCAN_WINDOW = 10  # secunde

    # Numărul de conexiuni pentru a declanșa alerta de brute force
    BRUTE_FORCE_THRESHOLD = 10
    BRUTE_FORCE_WINDOW = 30  # secunde

    # Volumul de date (bytes) pentru a declanșa alerta de trafic anormal
    TRAFFIC_VOLUME_THRESHOLD = 10 * 1024 * 1024  # 10 MB în 60 secunde
    TRAFFIC_VOLUME_WINDOW = 60  # secunde

    # Interfața de rețea pentru captură (None = auto-detectare)
    NETWORK_INTERFACE = os.environ.get('NETWORK_INTERFACE') or None

    # Auto-blocare IP la alerte critice / înalte
    AUTO_BLOCK_ENABLED = os.environ.get('AUTO_BLOCK_ENABLED', 'true').lower() == 'true'
    # Severitățile care declanșează auto-block
    AUTO_BLOCK_SEVERITY = ['critical', 'high']

    # Modul simulat (fără Scapy/drepturi root)
    SIMULATION_MODE = os.environ.get('SIMULATION_MODE', 'false').lower() == 'true'

    # Modul sniffer: 'simulated' | 'interface' | 'tzsp'
    # Dacă SNIFFER_MODE este setat, are prioritate față de SIMULATION_MODE
    SNIFFER_MODE = os.environ.get('SNIFFER_MODE', 'simulated')

    # Adresa și portul pentru listener-ul TZSP (TaZmen Sniffer Protocol)
    TZSP_LISTEN_ADDRESS = os.environ.get('TZSP_LISTEN_ADDRESS', '0.0.0.0')
    TZSP_PORT = int(os.environ.get('TZSP_PORT', 37008))

    # Notificări Telegram
    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
    TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
    TELEGRAM_ENABLED = os.environ.get('TELEGRAM_ENABLED', 'false').lower() == 'true'
    TELEGRAM_MIN_SEVERITY = os.environ.get('TELEGRAM_MIN_SEVERITY', 'critical')  # 'low', 'medium', 'high', 'critical'

    # Configurare MikroTik RouterOS API
    MIKROTIK_HOST = os.environ.get('MIKROTIK_HOST', '')
    MIKROTIK_PORT = int(os.environ.get('MIKROTIK_PORT', 8728))  # 8728 = plaintext, 8729 = SSL
    MIKROTIK_USERNAME = os.environ.get('MIKROTIK_USERNAME', 'admin')
    MIKROTIK_PASSWORD = os.environ.get('MIKROTIK_PASSWORD', '')
    MIKROTIK_ENABLED = os.environ.get('MIKROTIK_ENABLED', 'false').lower() == 'true'
    MIKROTIK_SYNC_INTERVAL = int(os.environ.get('MIKROTIK_SYNC_INTERVAL', 60))  # secunde

    # Monitorizare securitate externă (atacuri din internet)
    # Activat automat când MikroTik este activ
    EXTERNAL_MONITOR_ENABLED = os.environ.get('EXTERNAL_MONITOR_ENABLED', 'true').lower() == 'true'

    # Server syslog intern (primește log-uri firewall de la RouterOS prin UDP)
    SYSLOG_LISTEN_ADDRESS = os.environ.get('SYSLOG_LISTEN_ADDRESS', '0.0.0.0')
    SYSLOG_PORT = int(os.environ.get('SYSLOG_PORT', 514))

    # Setări detectare DNS Tunneling
    # Lungimea maximă permisă a subdomain-ului (caractere) — interogări cu subdomenii mai lungi declanșează alerta
    DNS_TUNNELING_MAX_SUBDOMAIN_LENGTH = int(os.environ.get('DNS_TUNNELING_MAX_SUBDOMAIN_LENGTH', 100))
    # Numărul de query-uri DNS unice în 60 de secunde care declanșează alerta
    DNS_TUNNELING_UNIQUE_QUERIES_THRESHOLD = int(os.environ.get('DNS_TUNNELING_UNIQUE_QUERIES_THRESHOLD', 100))
    # Servere DNS de încredere (listă separată prin virgulă) — interogările înspre acestea sunt ignorate
    DNS_TRUSTED_SERVERS = [
        s.strip()
        for s in os.environ.get('DNS_TRUSTED_SERVERS', '192.168.2.1,8.8.8.8,1.1.1.1').split(',')
        if s.strip()
    ]

    # Retenție pentru istoricul conexiunilor per IP (site-uri/aplicații accesate)
    # Intrările mai vechi decât acest prag sunt șterse periodic.
    IP_CONNECTION_RETENTION_DAYS = int(os.environ.get('IP_CONNECTION_RETENTION_DAYS', 30))
    # Retenție pentru agregările zilnice pe aplicație/site.
    APP_TRAFFIC_RETENTION_DAYS = int(os.environ.get('APP_TRAFFIC_RETENTION_DAYS', 180))
    # Limită de siguranță pentru actualizări bulk (protecție la payload-uri mari/abuzive)
    BULK_UPDATE_MAX_ITEMS = int(os.environ.get('BULK_UPDATE_MAX_ITEMS', 200))

    # -------------------------------------------------------------------------
    # Configurare ML (detectare anomalii bazată pe Machine Learning)
    # -------------------------------------------------------------------------
    # Activează/dezactivează complet modulul ML
    ML_ENABLED = os.environ.get('ML_ENABLED', 'true').lower() == 'true'
    # Pragul scorului Isolation Forest (fracție 0-1, înmulțit cu 100 în cod)
    # Exemplu: 0.6 → alertă generată când scorul depășește 60/100
    ML_ISOLATION_FOREST_THRESHOLD = float(os.environ.get('ML_ISOLATION_FOREST_THRESHOLD', 0.6))
    # Pragul scorului LOF (fracție 0-1) — folosit intern în combinarea scorurilor
    ML_LOF_THRESHOLD = float(os.environ.get('ML_LOF_THRESHOLD', 0.65))
    # Activează/dezactivează Autoencoder (necesită TensorFlow)
    ML_AUTOENCODER_ENABLED = os.environ.get('ML_AUTOENCODER_ENABLED', 'false').lower() == 'true'
    # Fereastra de colectare a caracteristicilor (minute)
    ML_FEATURE_WINDOW_MINUTES = int(os.environ.get('ML_FEATURE_WINDOW_MINUTES', 1))
    # Intervalul de reantrenare a modelelor (ore)
    ML_MODEL_RETRAIN_HOURS = int(os.environ.get('ML_MODEL_RETRAIN_HOURS', 24))
    # Numărul minim de puncte de date înainte de a începe scoring-ul
    ML_MIN_DATA_POINTS = int(os.environ.get('ML_MIN_DATA_POINTS', 100))
    # Intervalul minim între două evaluări ML per IP (secunde)
    ML_SCORING_INTERVAL_SECONDS = int(os.environ.get('ML_SCORING_INTERVAL_SECONDS', 60))


class DevelopmentConfig(Config):
    """Configurare pentru dezvoltare."""
    DEBUG = True
    SIMULATION_MODE = True  # Activăm modul simulat în dezvoltare
    # Cookies securizate doar dacă HTTPS e activ în development
    SESSION_COOKIE_SECURE = bool(os.environ.get('SSL_CERT') and os.environ.get('SSL_KEY'))
    PREFERRED_URL_SCHEME = 'https' if (os.environ.get('SSL_CERT') and os.environ.get('SSL_KEY')) else 'http'


class ProductionConfig(Config):
    """Configurare pentru producție."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True   # Cookie-ul de sesiune transmis doar prin HTTPS
    PREFERRED_URL_SCHEME = 'https'

    @classmethod
    def init_app(cls, app):
        """Validare configurare producție la pornire."""
        if app.config.get('SECRET_KEY') == _DEFAULT_SECRET_KEY:
            raise RuntimeError(
                "SECRET_KEY implicit detectat în producție. "
                "Setați variabila de mediu SECRET_KEY cu o valoare puternică "
                "(ex: python -c \"import secrets; print(secrets.token_hex(32))\")."
            )


# Dicționar de configurări disponibile
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
