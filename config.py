"""
Configurarea aplicației Flask pentru sistemul de securitate al rețelei școlare.
"""
import os
import warnings

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
            warnings.warn(
                "\n\n⚠️  ATENȚIE SECURITATE: SECRET_KEY nu este setat!\n"
                "   Setați variabila de mediu SECRET_KEY cu o valoare aleatorie puternică.\n"
                "   Generați una cu: python -c \"import secrets; print(secrets.token_hex(32))\"\n",
                stacklevel=2,
            )


# Dicționar de configurări disponibile
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
