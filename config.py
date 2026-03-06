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

    # Modul simulat (fără Scapy/drepturi root)
    SIMULATION_MODE = os.environ.get('SIMULATION_MODE', 'false').lower() == 'true'


class DevelopmentConfig(Config):
    """Configurare pentru dezvoltare."""
    DEBUG = True
    SIMULATION_MODE = True  # Activăm modul simulat în dezvoltare


class ProductionConfig(Config):
    """Configurare pentru producție."""
    DEBUG = False

    @property
    def SECRET_KEY(self):
        key = os.environ.get('SECRET_KEY')
        if not key:
            import warnings
            warnings.warn(
                "SECRET_KEY nu este setat ca variabilă de mediu! "
                "Utilizați o cheie secretă puternică în producție.",
                RuntimeWarning
            )
            return 'school-security-secret-key-2024'
        return key


# Dicționar de configurări disponibile
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
