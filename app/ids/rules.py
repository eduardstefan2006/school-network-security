"""
Regulile de detectare pentru IDS.
Aceste reguli sunt configurabile și definesc pragurile pentru detectarea amenințărilor.
"""
import os

# =============================================================================
# Reguli pentru detectarea Port Scanning
# =============================================================================
PORT_SCAN_RULES = {
    'enabled': True,
    # Numărul minim de porturi diferite accesate pentru a considera că este un scan
    'threshold': 45,           # Crescut de la 25 - detectare la 45 de porturi în 10 secunde
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
        23: 'Telnet',       # Protocol nesecurizat (text simplu) - monitorizat pentru detectarea accesului neautorizat
        3389: 'RDP',
        5900: 'VNC',
        # 80, 443, 8080 ELIMINATE - navigarea web normală declanșează fals pozitive
    },
    # Numărul de conexiuni eșuate / rapide pentru a declanșa alerta
    'threshold': 60,          # Crescut de la 20 - declanșare la 60 de conexiuni
    # Fereastra de timp în secunde
    'window_seconds': 60,     # Fereastră de 60 de secunde
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
    'threshold': 50,           # Crescut de la 20 - routerul MikroTik și switch-urile fac cereri ARP legitime
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
    # Router principal
    '192.168.2.1',      # MikroTik RB3011 "Scoala 2 Liesti"
    # Servere infrastructură
    '192.168.2.241',    # PiHole (server DNS)
    '192.168.2.242',    # LibreNMS (monitorizare SNMP)
    '192.168.2.243',    # SchoolSec (acest server)
    # NVR și camere supraveghere
    '192.168.2.80',     # NVR (Network Video Recorder)
    '192.168.2.91',     # Camera 1
    '192.168.2.92',     # Camera 2
    '192.168.2.93',     # Camera 3
    '192.168.2.96',     # Camera 6
    # Echipamente rețea (switch-uri)
    '192.168.2.5',      # Router Cisco
    '192.168.2.8',      # Switch Corp A Parter
    '192.168.2.9',      # Switch Corp A Etaj 2
    '192.168.2.10',     # Switch Corp B
    # Camere supraveghere (fost etichetat greșit ca AP)
    '192.168.2.160',    # Camera NVR Access
    '192.168.2.161',    # Camera Etajul 1 Stânga
    '192.168.2.162',    # Camera Parter Dreapta
    '192.168.2.163',    # Camera Etaj Grădiniță
    '192.168.2.164',    # Camera Intrare Secretariat
    '192.168.2.165',    # Camera Parter Stânga
    '192.168.2.166',    # Camera Etajul 1 Dreapta
    '192.168.2.167',    # Camera Intrare Elevi
    '192.168.2.168',    # Camera Etaj 2 Dreapta
    '192.168.2.169',    # Camera Etaj 2 Stânga
    '192.168.2.170',    # Cameră Sală Sport
    '192.168.2.171',    # Cameră Intrare Profesori
    '192.168.2.172',    # Cameră Teren Baschet
    '192.168.2.173',    # Cameră Intrare Elevi
    '192.168.2.174',    # Cameră Teren Sport
    '192.168.2.175',    # Cameră Poartă
    '192.168.2.176',    # Cameră Sală Sport intrare spate
    '192.168.2.177',    # Camera Parter/Etajul1
    '192.168.2.178',    # Camera Etaj1/Etaj2
    # Access Point-uri (routere TP-Link/Asus în modul AP pe VLAN-uri)
    '192.168.221.2',    # Router Sala 1 Parter
    '192.168.222.2',    # Router Sala 2 Parter
    '192.168.223.2',    # Router Sala 3 Parter
    '192.168.224.2',    # Router Sala 1 Etaj 1
    '192.168.225.2',    # Router Sala 2 Etaj 1
    '192.168.226.2',    # Router Sala 3 Etaj 1
    '192.168.227.2',    # Router Biologie Etaj 1
    '192.168.228.2',    # Router Sala 1 Etaj 2
    '192.168.229.2',    # Router Sala 2 Etaj 2
    '192.168.230.2',    # Router Fizica/Chimie Etaj 2
    '192.168.232.2',    # Router Sala 1 Corp B
    '192.168.233.2',    # Router Sala 2 Corp B
    '192.168.234.2',    # Router Gradinita
    '192.168.234.3',    # Router Asus Gradinita
    '192.168.235.2',    # Router Sala Sport
    '192.168.236.2',    # Router Secretariat
    '192.168.237.3',    # Router Psiholog
    '192.168.239.2',    # Router Cancelarie
    # DNS extern
    '1.1.1.1',          # Cloudflare DNS
    '8.8.8.8',          # Google DNS
]

# =============================================================================
# Reguli pentru detectarea DNS Tunneling
# =============================================================================
_dns_trusted_default = '192.168.2.1,8.8.8.8,1.1.1.1'
DNS_TUNNELING_RULES = {
    'enabled': False,  # Dezactivat temporar — VLAN-uri cu DNS central declanșau false positive-uri
    # Lungimea maximă permisă a subdomain-ului (caractere)
    # Configurabil prin variabila de mediu DNS_TUNNELING_MAX_SUBDOMAIN_LENGTH
    'max_subdomain_length': int(os.environ.get('DNS_TUNNELING_MAX_SUBDOMAIN_LENGTH', 150)),
    # Numărul de query-uri DNS unice care declanșează alerta
    # Configurabil prin variabila de mediu DNS_TUNNELING_UNIQUE_QUERIES_THRESHOLD
    'unique_queries_threshold': int(os.environ.get('DNS_TUNNELING_UNIQUE_QUERIES_THRESHOLD', 200)),
    # Fereastra de timp în secunde
    'window_seconds': 60,
    # Severitatea alertei
    'severity': 'high',
    # Servere DNS de încredere — query-urile DNS înspre aceste IP-uri NU declanșează alerta
    # Configurabil prin variabila de mediu DNS_TRUSTED_SERVERS (listă separată prin virgulă)
    'trusted_dns_servers': frozenset(
        s.strip()
        for s in os.environ.get('DNS_TRUSTED_SERVERS', _dns_trusted_default).split(',')
        if s.strip()
    ),
}

# =============================================================================
# Reguli pentru detectarea DHCP Spoofing (server DHCP rogue)
# =============================================================================
DHCP_RULES = {
    'enabled': True,
    # IP-urile serverelor DHCP legitime din rețea
    'legitimate_servers': ['192.168.2.1'],
    # Severitatea alertei
    'severity': 'critical',
}

# =============================================================================
# Reguli pentru detectarea Packet Flood (rata de pachete per IP)
# =============================================================================
PACKET_FLOOD_RULES = {
    'enabled': True,
    # Numărul maxim de pachete permis în fereastra de timp
    'threshold': 500,          # pachete
    # Fereastra de timp în secunde
    'window_seconds': 1,       # per secundă
    # Severitatea alertei
    'severity': 'high',
}

# =============================================================================
# Reguli pentru detectarea protocoalelor nesecurizate
# =============================================================================
INSECURE_PROTOCOL_RULES = {
    'enabled': True,
    # Porturile monitorizate și denumirile protocoalelor asociate
    'monitored_ports': {
        23: 'Telnet',
        21: 'FTP',
        110: 'POP3',
        143: 'IMAP',
        25: 'SMTP',
    },
    # Cooldown în secunde — alertează o dată la 10 minute per IP/port
    'cooldown_seconds': 600,
    # Severitatea alertei
    'severity': 'medium',
}

# =============================================================================
# Reguli pentru detectarea SYN Flood
# =============================================================================
SYN_FLOOD_RULES = {
    'enabled': True,
    # Numărul de conexiuni TCP care declanșează alerta
    'threshold': 200,
    # Fereastra de timp în secunde
    'window_seconds': 10,
    # Severitatea alertei
    'severity': 'critical',
}

# =============================================================================
# Reguli pentru monitorizarea securității externe (atacuri din internet)
# =============================================================================
EXTERNAL_PORT_SCAN_RULES = {
    'enabled': True,
    'threshold': 20,           # pachete droppate de la același IP
    'window_seconds': 60,
    'severity': 'high',
}

EXTERNAL_BRUTE_FORCE_RULES = {
    'enabled': True,
    'threshold': 5,            # tentative login eșuate
    'window_seconds': 300,     # 5 minute
    'severity': 'critical',
}

EXTERNAL_DDOS_RULES = {
    'enabled': True,
    'threshold': 1000,         # total pachete droppate
    'window_seconds': 60,
    'severity': 'critical',
}

ROUTER_HEALTH_RULES = {
    'enabled': True,
    'cpu_threshold': 80,       # procent
    'memory_threshold': 20,    # procent liber minim
    'severity_cpu': 'high',
    'severity_memory': 'medium',
}

# =============================================================================
# IP-uri de încredere pentru monitorizarea externă (tunnel-uri inter-școli, VPN)
# Login-urile și traficul de la aceste IP-uri NU generează alerte externe.
# =============================================================================
EXTERNAL_TRUSTED_IPS = [
    # Tunnel-uri IPIP
    '172.0.2.1',    # Acasă
    '172.0.2.2',    # Acasă (capăt local)
    '172.2.4.1',    # Școala 4 (capăt local)
    '172.2.4.2',    # Școala 4
    '172.2.6.1',    # Școala Hanu Corp A2 (capăt local)
    '172.2.6.2',    # Școala Hanu Corp A2
    # Tunnel-uri GRE
    '172.1.2.1',    # Școala 1
    '172.1.2.2',    # Școala 1 (capăt local)
    '172.2.3.1',    # Școala 3 (capăt local)
    '172.2.3.2',    # Școala 3
    '172.2.5.1',    # Grădinița 3 (capăt local)
    '172.2.5.2',    # Grădinița 3
    '172.2.7.1',    # Școala Hanu Corp B (capăt local)
    '172.2.7.2',    # Școala Hanu Corp B
    # IP-uri publice ale celorlalte școli (pot face login legitim pe router)
    '82.79.117.30',       # Școala 4
    '86.120.144.133',     # Școala Hanu Corp A
    '86.120.144.134',     # Școala Hanu Corp B
]

# Subnet-uri VPN de încredere (WireGuard + L2TP/PPTP)
EXTERNAL_TRUSTED_SUBNETS = [
    '192.168.89.0/24',      # VPN L2TP/PPTP pool
    '192.168.250.0/29',     # WireGuard 1 (Grigoras Mirela)
    '192.168.251.0/29',     # WireGuard 2 (Contabil 1)
    '192.168.252.0/29',     # WireGuard 3 (Director)
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