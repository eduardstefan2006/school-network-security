"""
Configurarea aplicației Flask pentru sistemul de securitate al rețelei școlare.
"""
import os

# Directorul de bază al proiectului
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Configurare de bază."""
    # Cheie secretă pentru sesiuni Flask
    # IMPORTANT: Setați variabila de mediu SECRET_KEY în producție!
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'school-security-secret-key-2024'

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


class DevelopmentConfig(Config):
    """Configurare pentru dezvoltare."""
    DEBUG = True
    SIMULATION_MODE = True  # Activăm modul simulat în dezvoltare


class ProductionConfig(Config):
    """Configurare pentru producție."""
    DEBUG = False


# Dicționar de configurări disponibile
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
