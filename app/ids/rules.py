"""
Regulile de detectare pentru IDS.
Aceste reguli sunt configurabile și definesc pragurile pentru detectarea amenințărilor.
"""

# =============================================================================
# Reguli pentru detectarea Port Scanning
# =============================================================================
PORT_SCAN_RULES = {
    'enabled': True,
    # Numărul minim de porturi diferite accesate pentru a considera că este un scan
    'threshold': 15,
    # Fereastra de timp în secunde
    'window_seconds': 10,
    # Severitatea alertei
    'severity': 'high',
    # Porturile comune care sunt mereu scanate (mai puțin relevante)
    'common_ports': [80, 443, 22, 21, 25, 110, 143, 53],
}

# =============================================================================
# Reguli pentru detectarea Brute Force
# =============================================================================
BRUTE_FORCE_RULES = {
    'enabled': True,
    # Porturile monitorizate pentru brute force
    'monitored_ports': {
        22: 'SSH',
        21: 'FTP',
        3389: 'RDP',
        80: 'HTTP',
        443: 'HTTPS',
        8080: 'HTTP-Alt',
    },
    # Numărul de conexiuni eșuate / rapide pentru a declanșa alerta
    'threshold': 10,
    # Fereastra de timp în secunde
    'window_seconds': 30,
    # Severitatea alertei
    'severity': 'high',
}

# =============================================================================
# Reguli pentru detectarea traficului anormal (volum mare)
# =============================================================================
HIGH_TRAFFIC_RULES = {
    'enabled': True,
    # Volumul maxim de bytes în fereastra de timp (10 MB)
    'threshold_bytes': 10 * 1024 * 1024,
    # Fereastra de timp în secunde
    'window_seconds': 60,
    # Severitatea alertei
    'severity': 'medium',
}

# =============================================================================
# Reguli pentru detectarea scanărilor ARP (ARP spoofing)
# =============================================================================
ARP_RULES = {
    'enabled': True,
    # Numărul de cereri ARP pentru a detecta un sweep
    'threshold': 20,
    # Fereastra de timp în secunde
    'window_seconds': 5,
    # Severitatea alertei
    'severity': 'critical',
}

# =============================================================================
# Lista albă de IP-uri (nu se generează alerte pentru acestea)
# =============================================================================
WHITELIST_IPS = [
    '127.0.0.1',
    '::1',
    # Adaugă IP-urile serverelor de rețea ale școlii
]

# =============================================================================
# Porturile considerate sensibile (accesul la acestea generează loguri)
# =============================================================================
SENSITIVE_PORTS = [
    22,    # SSH
    23,    # Telnet
    21,    # FTP
    3389,  # RDP
    5900,  # VNC
    1433,  # MSSQL
    3306,  # MySQL
    5432,  # PostgreSQL
    6379,  # Redis
    27017, # MongoDB
]
