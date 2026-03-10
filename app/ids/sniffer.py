"""
Modulul de captură a pachetelor de rețea.
Folosește Scapy pentru captură reală sau generează trafic simulat pentru testare.
"""
import json
import os
import re
import threading
import time
import random
import socket
import ipaddress
from datetime import datetime, timezone
from collections import defaultdict

# =============================================================================
# Mapare hostname → nume aplicație (cu emoji-uri)
# =============================================================================
_APP_NAMES = {
    'facebook.com': '📘 Facebook',
    'fbcdn.net': '📘 Facebook',
    'fb.com': '📘 Facebook',
    'instagram.com': '📸 Instagram',
    'cdninstagram.com': '📸 Instagram',
    'tiktok.com': '🎵 TikTok',
    'tiktokcdn.com': '🎵 TikTok',
    'musical.ly': '🎵 TikTok',
    'whatsapp.com': '💬 WhatsApp',
    'whatsapp.net': '💬 WhatsApp',
    'youtube.com': '▶️ YouTube',
    'ytimg.com': '▶️ YouTube',
    'googlevideo.com': '▶️ YouTube',
    'yt3.ggpht.com': '▶️ YouTube',
    'google.com': '🔍 Google',
    'googleapis.com': '🔍 Google',
    'gstatic.com': '🔍 Google',
    'gmail.com': '📧 Gmail',
    'googlemail.com': '📧 Gmail',
    'twitter.com': '🐦 Twitter/X',
    'twimg.com': '🐦 Twitter/X',
    't.co': '🐦 Twitter/X',
    'x.com': '🐦 Twitter/X',
    'snapchat.com': '👻 Snapchat',
    'snap.com': '👻 Snapchat',
    'netflix.com': '🎬 Netflix',
    'nflxvideo.net': '🎬 Netflix',
    'spotify.com': '🎵 Spotify',
    'scdn.co': '🎵 Spotify',
    'discord.com': '🎮 Discord',
    'discordapp.com': '🎮 Discord',
    'discord.gg': '🎮 Discord',
    'telegram.org': '✈️ Telegram',
    'microsoft.com': '🪟 Microsoft',
    'office.com': '🪟 Microsoft',
    'live.com': '🪟 Microsoft',
    'outlook.com': '🪟 Microsoft',
    'windows.com': '🪟 Microsoft',
    'apple.com': '🍎 Apple',
    'icloud.com': '🍎 iCloud',
    'akamai.net': '☁️ CDN/Akamai',
    'cloudflare.com': '☁️ Cloudflare',
    'twitch.tv': '🎮 Twitch',
    'amazon.com': '📦 Amazon',
    'amazonaws.com': '☁️ AWS',
    'zoom.us': '📹 Zoom',
    'teams.microsoft.com': '🪟 Microsoft Teams',
    'linkedin.com': '💼 LinkedIn',
    'pinterest.com': '📌 Pinterest',
    'reddit.com': '🤖 Reddit',
    'redd.it': '🤖 Reddit',
    'wikipedia.org': '📖 Wikipedia',
    'wikimedia.org': '📖 Wikipedia',
}


def _get_app_name(hostname: str):
    """Returnează numele aplicației pentru un hostname dat."""
    if not hostname:
        return None
    hostname = hostname.lower().rstrip('.')
    for domain, app_name in _APP_NAMES.items():
        if hostname == domain or hostname.endswith('.' + domain):
            return app_name
    return None

# Statistici globale despre trafic (în memorie)
traffic_stats = {
    'total_packets': 0,
    'protocols': defaultdict(int),
    'top_sources': defaultdict(int),
    'top_destinations': defaultdict(int),
    'bytes_total': 0,
    'last_packets': [],  # Ultimele 100 pachete
    'start_time': datetime.now(timezone.utc).isoformat(),
}

# Lock pentru acces thread-safe la statistici
_stats_lock = threading.Lock()

# Flag pentru oprirea snifferului
_running = False
_sniffer_thread = None

# =============================================================================
# Buffer pentru actualizarea dispozitivelor (flush la DB la fiecare 30 secunde)
# =============================================================================
# Structura: { ip: {'mac': str|None, 'packets': int, 'bytes': int, 'last_seen': datetime} }
_device_buffer = {}
_device_buffer_lock = threading.Lock()
_last_device_flush = time.monotonic()
_DEVICE_FLUSH_INTERVAL = 30  # secunde

# Timer pentru curățarea periodică a dispozitivelor mobile inactive (MAC randomizat)
_last_mobile_cleanup = 0
_MOBILE_CLEANUP_INTERVAL = 6 * 3600  # 6 ore în secunde

# Timer pentru deduplicarea periodică a dispozitivelor mobile (la fiecare 5 minute)
_last_dedup_cleanup = 0
_DEDUP_CLEANUP_INTERVAL = 5 * 60  # 5 minute în secunde
_dedup_running = False  # Flag pentru a evita rulări concurente

# =============================================================================
# Cache DNS și buffer conexiuni (flush periodic la DB)
# =============================================================================
# Cache DNS: ip_destinatie -> hostname (ultimul hostname rezolvat)
_dns_cache: dict = {}
_dns_cache_lock = threading.Lock()

# Cache hostname per IP (din DHCP opțiunea 12 sau DNS PTR)
_device_hostname_cache: dict = {}
_device_hostname_cache_lock = threading.Lock()

# Buffer conexiuni per (source_ip, hostname)
_connections_buffer: dict = {}
_connections_lock = threading.Lock()
_last_connections_flush = 0
_CONNECTIONS_FLUSH_INTERVAL = 30  # secunde

# =============================================================================
# Cache hint trafic mobil per IP (porturi specifice dispozitivelor mobile)
# =============================================================================
# Porturi FCM/push Google (Google Play push notifications)
MOBILE_INDICATOR_PORTS = frozenset([5228, 5229, 5230])

# Cache: ip -> True dacă traficul sugerează un dispozitiv mobil
_mobile_traffic_hints: dict = {}
_mobile_traffic_lock = threading.Lock()


def _update_mobile_traffic_hint(src_ip: str, dst_port):
    """Înregistrează dacă un IP accesează porturi tipice pentru dispozitive mobile."""
    if dst_port in MOBILE_INDICATOR_PORTS:
        with _mobile_traffic_lock:
            _mobile_traffic_hints[src_ip] = True


def _update_connection(source_ip: str, hostname: str, size: int):
    """Actualizează buffer-ul de conexiuni pentru un IP sursă și hostname."""
    if not source_ip or not hostname:
        return
    app_name = _get_app_name(hostname)
    key = (source_ip, hostname)
    with _connections_lock:
        if key not in _connections_buffer:
            _connections_buffer[key] = {
                'bytes': 0,
                'packets': 0,
                'app_name': app_name,
                'last_seen': datetime.now(timezone.utc),
            }
        _connections_buffer[key]['bytes'] += size
        _connections_buffer[key]['packets'] += 1
        _connections_buffer[key]['last_seen'] = datetime.now(timezone.utc)


def _maybe_flush_connections(app):
    """Flush periodic al conexiunilor din buffer în baza de date."""
    global _last_connections_flush
    now = time.monotonic()
    if now - _last_connections_flush < _CONNECTIONS_FLUSH_INTERVAL:
        return
    _last_connections_flush = now

    with _connections_lock:
        snapshot = dict(_connections_buffer)
        _connections_buffer.clear()

    if not snapshot:
        return

    def _do_flush():
        from app.models import IPConnection
        from app import db
        with app.app_context():
            try:
                for (src_ip, hostname), data in snapshot.items():
                    conn = IPConnection.query.filter_by(
                        source_ip=src_ip, hostname=hostname
                    ).first()
                    if conn:
                        conn.bytes_total += data['bytes']
                        conn.packets_count += data['packets']
                        conn.last_seen = data['last_seen']
                        if not conn.app_name and data['app_name']:
                            conn.app_name = data['app_name']
                    else:
                        conn = IPConnection(
                            source_ip=src_ip,
                            hostname=hostname,
                            app_name=data['app_name'],
                            bytes_total=data['bytes'],
                            packets_count=data['packets'],
                            last_seen=data['last_seen'],
                        )
                        db.session.add(conn)
                db.session.commit()
            except Exception as e:
                print(f"[Sniffer] Eroare flush conexiuni: {e}")
                db.session.rollback()

    threading.Thread(target=_do_flush, daemon=True).start()


def _is_private_ip(ip_str):
    """Verifică dacă un IP este privat (RFC1918)."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


# Mapare statică subnet → VLAN-ID (din configurația MikroTik setari.rsc)
_VLAN_MAP = [
    (ipaddress.ip_network('192.168.231.0/26'), 200),  # LaboratorInfo
    (ipaddress.ip_network('192.168.221.0/28'), 201),  # Sala1Parter
    (ipaddress.ip_network('192.168.222.0/27'), 202),  # Sala2Parter
    (ipaddress.ip_network('192.168.223.0/28'), 203),  # Sala3Parter
    (ipaddress.ip_network('192.168.224.0/28'), 204),  # Sala1Etaj1
    (ipaddress.ip_network('192.168.225.0/28'), 205),  # Sala2Etaj1
    (ipaddress.ip_network('192.168.226.0/28'), 206),  # Sala3Etaj1
    (ipaddress.ip_network('192.168.227.0/28'), 207),  # BiologieEtaj1
    (ipaddress.ip_network('192.168.228.0/28'), 208),  # Sala1Etaj2
    (ipaddress.ip_network('192.168.229.0/28'), 209),  # Sala2Etaj2
    (ipaddress.ip_network('192.168.230.0/28'), 210),  # Fizica/ChimieEtaj2
    (ipaddress.ip_network('192.168.232.0/28'), 212),  # Sala1CorpB
    (ipaddress.ip_network('192.168.233.0/28'), 213),  # Sala2CorpB
    (ipaddress.ip_network('192.168.234.0/27'), 214),  # Gradinita
    (ipaddress.ip_network('192.168.235.0/27'), 215),  # SalaSport
    (ipaddress.ip_network('192.168.236.0/27'), 216),  # Secretariat
    (ipaddress.ip_network('192.168.237.0/28'), 217),  # Psiholog
]


def _get_vlan_from_ip(ip_str):
    """Returnează VLAN-ID-ul pentru un IP pe baza mapării statice subnet→VLAN.

    Returnează None dacă IP-ul nu aparține niciunui subnet VLAN cunoscut
    (ex: 192.168.2.x - rețea principală fără tag VLAN, sau 192.168.239.x - Cancelarie).
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for network, vlan_id in _VLAN_MAP:
        if ip in network:
            return vlan_id
    return None


# =============================================================================
# Detecție automată AP pe baza vendor OUI (TP-Link / ASUS)
# =============================================================================

def normalize_mac(mac: str) -> str | None:
    """Normalizează un MAC address la formatul aa:bb:cc:dd:ee:ff (lowercase, separator ':').

    Args:
        mac: String MAC address în orice format (cu ':', '-', '.' sau fără separator).
    Returns:
        MAC normalizat ca string 'aa:bb:cc:dd:ee:ff', sau None dacă input-ul e invalid.
    """
    if not mac:
        return None
    cleaned = mac.replace(':', '').replace('-', '').replace('.', '').lower()
    if len(cleaned) != 12:
        return None
    try:
        int(cleaned, 16)
    except ValueError:
        return None
    return ':'.join(cleaned[i:i + 2] for i in range(0, 12, 2))


def get_mac_oui(mac: str) -> str | None:
    """Returnează OUI-ul (primii 3 octeți) dintr-un MAC address, ca string uppercase (ex: 'AA:BB:CC').

    Args:
        mac: String MAC address în orice format acceptat de normalize_mac.
    Returns:
        OUI ca string 'AA:BB:CC' (uppercase), sau None dacă MAC-ul e invalid sau None.
    """
    normalized = normalize_mac(mac)
    if normalized is None:
        return None
    return normalized[:8].upper()


def _load_ap_vendor_ouis() -> dict:
    """Încarcă OUI-urile AP vendor din data/oui_vendors.json (dacă există), cu fallback la o listă minimă.

    Returns:
        Dict cu structura {vendor_name: [oui_string, ...]} unde vendor_name este
        cheia furnizorului (ex: 'tplink', 'asus') și fiecare OUI e un string uppercase
        de forma 'AA:BB:CC'. Cheile care încep cu '_' (ex: '_comment') sunt excluse.
        Dacă JSON-ul conține cheia '_ap_vendors', sunt încărcați doar vendorii listați acolo.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    json_path = os.path.join(base_dir, 'data', 'oui_vendors.json')
    if os.path.isfile(json_path):
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            ap_vendors = data.get('_ap_vendors')
            if ap_vendors:
                return {
                    vendor: [oui.upper() for oui in data[vendor]]
                    for vendor in ap_vendors
                    if vendor in data
                }
            return {
                vendor: [oui.upper() for oui in ouis]
                for vendor, ouis in data.items()
                if not vendor.startswith('_')
            }
        except Exception as e:
            print(f"[Sniffer] Eroare la încărcarea OUI-urilor din {json_path}: {e}")
    # Fallback minimal (câteva OUI-uri reprezentative)
    return {
        'tplink': [
            '50:C7:BF', 'EC:08:6B', '54:AF:97', '18:D6:C7', '14:CF:92',
            '64:70:02', 'AC:84:C6', '98:DA:C4', 'B0:BE:76', '60:32:B1',
        ],
        'asus': [
            '04:92:26', '74:D0:2B', 'B0:6E:BF', '6C:F3:7F', '2C:FD:A1',
            '50:46:5D', 'AC:22:0B', '00:11:2F', '00:1A:92', '14:DA:E9',
        ],
    }


def _load_mobile_vendor_ouis() -> dict:
    """Încarcă OUI-urile producătorilor de dispozitive mobile din data/oui_vendors.json.

    Returns:
        Dict cu structura {vendor_name: [oui_string, ...]} pentru vendorii listați
        în cheia '_mobile_vendors' din JSON. Returnează dict gol dacă fișierul nu există
        sau cheia '_mobile_vendors' lipsește.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    json_path = os.path.join(base_dir, 'data', 'oui_vendors.json')
    if os.path.isfile(json_path):
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            mobile_vendors = data.get('_mobile_vendors', [])
            return {
                vendor: [oui.upper() for oui in data[vendor]]
                for vendor in mobile_vendors
                if vendor in data
            }
        except Exception as e:
            print(f"[Sniffer] Eroare la încărcarea OUI-urilor mobile din {json_path}: {e}")
    return {}


def _load_camera_vendor_ouis() -> dict:
    """Încarcă OUI-urile camerelor de supraveghere din data/oui_vendors.json.

    Returns:
        Dict cu structura {vendor_name: [oui_string, ...]} pentru vendorii listați
        în cheia '_camera_vendors' din JSON. Returnează dict gol dacă fișierul nu există
        sau cheia '_camera_vendors' lipsește.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    json_path = os.path.join(base_dir, 'data', 'oui_vendors.json')
    if os.path.isfile(json_path):
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            camera_vendors = data.get('_camera_vendors', [])
            return {
                vendor: [oui.upper() for oui in data[vendor]]
                for vendor in camera_vendors
                if vendor in data and isinstance(data[vendor], list)
            }
        except Exception as e:
            print(f"[Sniffer] Eroare la încărcarea OUI-urilor camere din {json_path}: {e}")
    return {}


_AP_VENDOR_OUIS = _load_ap_vendor_ouis()

# Set plat de OUI-uri AP pentru lookup O(1)
_AP_OUI_SET = frozenset(
    oui for ouis in _AP_VENDOR_OUIS.values() for oui in ouis
)

_MOBILE_VENDOR_OUIS = _load_mobile_vendor_ouis()

# Set plat de OUI-uri mobile pentru lookup O(1)
_MOBILE_OUI_SET = frozenset(
    oui for ouis in _MOBILE_VENDOR_OUIS.values() for oui in ouis
)

_CAMERA_VENDOR_OUIS = _load_camera_vendor_ouis()

# Set plat de OUI-uri camere de supraveghere pentru lookup O(1)
_CAMERA_OUI_SET = frozenset(
    oui for ouis in _CAMERA_VENDOR_OUIS.values() for oui in ouis
)

# Pattern regex pentru hostname-uri tipice de dispozitive mobile
_MOBILE_HOSTNAME_RE = re.compile(
    r'(iphone|ipad|ipod|android|galaxy|samsung|pixel|nexus|oneplus|huawei|xiaomi|'
    r'redmi|oppo|vivo|motorola|moto[-\s]?\w{0,20}|nokia|realme|honor|mi[-\s]?\d|'
    r'sm[-\s]?\w+|rne[-\s]?\w+|lge[-\s]?\w+|'
    r'\bsm-[a-z]\d{3,4}\b|'
    r's\d{2}s?[-\s]|a\d{2,3}s?[-\s]|'
    r's\d{2}s?$|a\d{2,3}s?$|'
    r'poco[-\w]*|'
    r'rmx\d+|'
    r'cph\d+|'
    r'v\d{4}[a-z]?|'
    r'redmi[-\s]?note|'
    r'honor[-\s]?\w+|'
    r'lenovo[-\s]?\w+|'
    r'phone|mobile|smartphone)',
    re.IGNORECASE
)


def _is_randomized_mac(mac: str | None) -> bool:
    """Returnează True dacă MAC-ul pare a fi randomizat (locally administered address - LAA bit).

    Un MAC randomizat are bitul 1 (LAA) al primului octet setat.
    Telefoanele moderne (Android 10+, iOS 14+) folosesc MAC randomizat pe Wi-Fi.
    Ex: 2A:xx, 6E:xx, BE:xx, DA:xx etc.

    Args:
        mac: Adresa MAC în orice format acceptat de normalize_mac, sau None.
    Returns:
        True dacă MAC-ul este locally administered (randomizat), False altfel.
    """
    if not mac:
        return False
    normalized = normalize_mac(mac)
    if not normalized:
        return False
    first_byte = int(normalized.split(':')[0], 16)
    return bool(first_byte & 0x02)


def _hostname_suggests_mobile(hostname: str | None) -> bool:
    """Returnează True dacă hostname-ul sugerează un dispozitiv mobil.

    Caută pattern-uri tipice în hostname-urile telefoanelor și tabletelor:
    iPhone, iPad, Android, Galaxy, Pixel, Huawei, Xiaomi, OnePlus etc.

    Args:
        hostname: Hostname-ul dispozitivului (din DHCP opțiunea 12 sau DNS), sau None.
    Returns:
        True dacă hostname-ul conține un pattern specific unui dispozitiv mobil.
    """
    if not hostname:
        return False
    return bool(_MOBILE_HOSTNAME_RE.search(hostname))


def _looks_like_ap(mac: str | None, vlan_id: int | None, ip: str | None) -> bool:
    """Returnează True dacă dispozitivul pare a fi un AP (vendor TP-Link/ASUS pe un VLAN).

    Criteriu: MAC aparține unui vendor AP (pe baza OUI) ȘI
              dispozitivul este pe un VLAN (vlan_id prezent sau IP în subnet VLAN cunoscut).

    Args:
        mac: Adresa MAC a dispozitivului (orice format), sau None dacă nu este cunoscută.
        vlan_id: ID-ul VLAN detectat din Dot1Q, sau None dacă nu e prezent.
        ip: Adresa IP ca string, folosită ca fallback pentru detecția VLAN din subnet.
    Returns:
        True dacă OUI-ul MAC aparține unui vendor AP cunoscut (TP-Link/ASUS) și
        dispozitivul se află pe un VLAN (vlan_id furnizat sau IP aparține unui subnet VLAN din _VLAN_MAP).
        False în orice alt caz (MAC lipsă, OUI necunoscut, sau nu e pe VLAN).
    """
    if not mac:
        return False
    oui = get_mac_oui(mac)
    if oui not in _AP_OUI_SET:
        return False
    if vlan_id is not None:
        return True
    if ip and _get_vlan_from_ip(ip) is not None:
        return True
    return False


def _looks_like_mobile(mac: str | None) -> bool:
    """Returnează True dacă dispozitivul pare a fi un telefon sau tabletă mobilă.

    Criteriu: MAC aparține unui producător de dispozitive mobile (pe baza OUI) —
              Apple (iPhone/iPad), Samsung, Xiaomi, OnePlus, Huawei, OPPO, Vivo sau Motorola.

    Args:
        mac: Adresa MAC a dispozitivului (orice format), sau None dacă nu este cunoscută.
    Returns:
        True dacă OUI-ul MAC aparține unui producător de dispozitive mobile cunoscut.
        False în orice alt caz (MAC lipsă, OUI necunoscut sau producător non-mobil).
    """
    if not mac:
        return False
    oui = get_mac_oui(mac)
    return oui in _MOBILE_OUI_SET


def _looks_like_camera(mac: str | None) -> bool:
    """Returnează True dacă dispozitivul pare a fi o cameră de supraveghere.

    Criteriu: MAC aparține unui producător de camere IP (pe baza OUI) —
              Kedacom/Tiandy (E0:61:B2, C0:39:5A) sau NVR (FC:5F:49).

    Args:
        mac: Adresa MAC a dispozitivului (orice format), sau None dacă nu este cunoscută.
    Returns:
        True dacă OUI-ul MAC aparține unui producător de camere de supraveghere cunoscut.
        False în orice alt caz (MAC lipsă, OUI necunoscut sau producător non-cameră).
    """
    if not mac:
        return False
    oui = get_mac_oui(mac)
    return oui in _CAMERA_OUI_SET


# Access Point-uri (routere TP-Link/Asus în modul AP pe VLAN-uri)
# Menținut pentru compatibilitate inversă; detecția automată OUI are prioritate.
_AP_IPS = {
    '192.168.221.2',  # Router Sala 1 Parter (TP-Link)
    '192.168.222.2',  # Router Sala 2 Parter (TP-Link)
    '192.168.223.2',  # Router Sala 3 Parter (TP-Link)
    '192.168.224.2',  # Router Sala 1 Etaj 1 (TP-Link)
    '192.168.225.2',  # Router Sala 2 Etaj 1 (TP-Link)
    '192.168.226.2',  # Router Sala 3 Etaj 1 (TP-Link)
    '192.168.227.2',  # Router Biologie Etaj 1 (TP-Link)
    '192.168.228.2',  # Router Sala 1 Etaj 2 (TP-Link)
    '192.168.229.2',  # Router Sala 2 Etaj 2 (TP-Link)
    '192.168.230.2',  # Router Fizica/Chimie Etaj 2 (TP-Link)
    '192.168.231.2',  # Router Laborator Info (TP-Link)
    '192.168.232.2',  # Router Sala 1 Corp B (Asus)
    '192.168.233.2',  # Router Sala 2 Corp B (Asus)
    '192.168.234.2',  # Router Gradinita (TP-Link)
    '192.168.234.3',  # Router Asus Gradinita (Asus)
    '192.168.235.2',  # Router Sala Sport (Asus)
    '192.168.236.2',  # Router Secretariat
    '192.168.237.2',  # Router Psiholog (TP-Link)
    '192.168.239.2',  # Router Cancelarie
}

# Tipuri de dispozitive cu clasificare fixă care nu trebuie reclasificate
# automat pe baza VLAN-ului (infrastructură de rețea)
_FIXED_DEVICE_TYPES = frozenset({'ap', 'router', 'switch', 'server', 'camera'})


def _detect_device_type(ip_str, mac=None, vlan_id=None, hostname=None):
    """Auto-detectează tipul dispozitivului pe baza MAC (OUI vendor), IP, VLAN și hostname.

    Prioritate de detecție:
    1. Dacă MAC aparține unui vendor AP (TP-Link/ASUS) și dispozitivul e pe un VLAN → 'ap'
    2. IP hardcodat (router, switch, cameră, server, AP din _AP_IPS)
    3. Dacă MAC aparține unui producător de camere de supraveghere (Kedacom/Tiandy) → 'camera'
    4. Dacă MAC aparține unui producător de dispozitive mobile (Apple, Samsung, etc.) → 'mobile'
    5. Dacă hostname-ul (DHCP/DNS) sugerează un dispozitiv mobil → 'mobile'
    6. Dacă MAC-ul este randomizat (LAA bit setat) și dispozitivul e pe un subnet VLAN client → 'mobile'
    7. Fallback → 'client'
    """
    # 1. Detecție automată AP pe baza OUI + VLAN (are prioritate față de IP)
    if _looks_like_ap(mac, vlan_id, ip_str):
        return 'ap'
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return 'unknown'

    ip_int = int(ip)

    def _ip_int(addr):
        return int(ipaddress.ip_address(addr))

    # Router principal
    if ip_str == '192.168.2.1':
        return 'router'
    # Switch-uri și Cisco router
    if ip_str in ('192.168.2.5', '192.168.2.8', '192.168.2.9', '192.168.2.10'):
        return 'switch'
    # NVR și Camere supraveghere: .80, .91-.96, .160-.178
    if ip_str == '192.168.2.80':
        return 'camera'
    if _ip_int('192.168.2.91') <= ip_int <= _ip_int('192.168.2.96'):
        return 'camera'
    if _ip_int('192.168.2.160') <= ip_int <= _ip_int('192.168.2.178'):
        return 'camera'
    # Servere: .241-.243
    if _ip_int('192.168.2.241') <= ip_int <= _ip_int('192.168.2.243'):
        return 'server'
    # Access Point-uri (routere TP-Link/Asus în modul AP pe VLAN-uri)
    if ip_str in _AP_IPS:
        return 'ap'

    # 3. Detecție automată camere de supraveghere pe baza OUI producător
    if _looks_like_camera(mac):
        return 'camera'

    # 4. Detecție automată dispozitive mobile pe baza OUI producător (MAC real)
    if _looks_like_mobile(mac):
        return 'mobile'

    # 5. Detecție pe baza hostname-ului (DHCP opțiunea 12 sau cache DNS)
    # Dacă hostname-ul nu e furnizat explicit, consultăm cache-ul global
    effective_hostname = hostname
    if not effective_hostname:
        with _device_hostname_cache_lock:
            effective_hostname = _device_hostname_cache.get(ip_str)
    if _hostname_suggests_mobile(effective_hostname):
        return 'mobile'

    # 6. Detecție pe baza MAC randomizat (LAA bit) — telefoane moderne cu privacy MAC
    # Aplicăm doar dacă dispozitivul este pe un subnet VLAN (rețea Wi-Fi de clienți)
    # și nu e pe subnet-ul principal 192.168.2.x (infrastructură)
    if _is_randomized_mac(mac) and _get_vlan_from_ip(ip_str) is not None:
        return 'mobile'

    # 7. Hint din trafic (porturi mobile) - doar pe subnet VLAN
    if _mobile_traffic_hints.get(ip_str) and _get_vlan_from_ip(ip_str) is not None:
        return 'mobile'

    return 'client'


def _update_device_buffer(ip, mac, size, vlan_id=None, hostname=None):
    """Actualizează buffer-ul de dispozitive în memorie (non-blocant)."""
    if not ip or not _is_private_ip(ip):
        return
    now = datetime.utcnow()
    # Dacă VLAN-ul nu a fost detectat din Dot1Q, calculăm fallback-ul static
    static_vlan = _get_vlan_from_ip(ip) if vlan_id is None else None
    # Actualizăm cache-ul de hostname dacă avem un hostname nou
    if hostname:
        with _device_hostname_cache_lock:
            _device_hostname_cache[ip] = hostname
    with _device_buffer_lock:
        if ip in _device_buffer:
            entry = _device_buffer[ip]
            entry['packets'] += 1
            entry['bytes'] += size
            entry['last_seen'] = now
            if mac and not entry.get('mac'):
                entry['mac'] = mac
            if hostname and not entry.get('hostname'):
                entry['hostname'] = hostname
            if vlan_id is not None:
                # Dot1Q are prioritate - actualizăm întotdeauna
                entry['vlan_id'] = vlan_id
            elif entry.get('vlan_id') is None and static_vlan is not None:
                # Aplicăm maparea statică doar dacă nu există deja un VLAN setat
                entry['vlan_id'] = static_vlan
        else:
            _device_buffer[ip] = {
                'mac': mac,
                'hostname': hostname,
                'packets': 1,
                'bytes': size,
                'last_seen': now,
                'is_new': True,
                'vlan_id': vlan_id if vlan_id is not None else static_vlan,
            }


def _flush_device_buffer(app):
    """Scrie buffer-ul de dispozitive în baza de date."""
    global _last_device_flush
    with _device_buffer_lock:
        # Facem o copie profundă a valorilor înainte de a reseta contoarele
        snapshot = {ip: dict(entry) for ip, entry in _device_buffer.items()}
        # Resetăm contoarele incrementale (păstrăm intrările, dar resetăm delta)
        for entry in _device_buffer.values():
            entry['packets'] = 0
            entry['bytes'] = 0
            entry['is_new'] = False

    if not snapshot:
        return

    try:
        with app.app_context():
            from app.models import NetworkDevice, Alert, SecurityLog
            from app import db
            from app.ids.rules import WHITELIST_IPS

            # Flag: dacă apare un dispozitiv nou cu MAC deja existent, rulăm deduplicarea
            _trigger_deduplication = False

            for ip, data in snapshot.items():
                try:
                    device = NetworkDevice.query.filter_by(ip_address=ip).first()
                    if device:
                        device.last_seen = data['last_seen']
                        device.total_packets = (device.total_packets or 0) + data['packets']
                        device.total_bytes = (device.total_bytes or 0) + data['bytes']
                        mac_updated = False
                        if data.get('mac') and not device.mac_address:
                            device.mac_address = data['mac']
                            mac_updated = True
                        hostname_updated = False
                        if data.get('hostname') and not device.hostname:
                            device.hostname = data['hostname']
                            hostname_updated = True
                        if data.get('vlan_id') is not None:
                            device.vlan = str(data['vlan_id'])
                        elif device.vlan is None:
                            fallback_vlan = _get_vlan_from_ip(ip)
                            if fallback_vlan is not None:
                                device.vlan = str(fallback_vlan)
                        # Reclasifică dispozitivul dacă tocmai am aflat MAC-ul, hostname-ul sau VLAN-ul,
                        # sau dacă tipul e 'client' și avem acum MAC/hostname (posibil mobil nedetectat)
                        should_reclassify = (
                            mac_updated
                            or hostname_updated
                            or (data.get('vlan_id') is not None and device.device_type not in _FIXED_DEVICE_TYPES)
                            or (device.device_type == 'client' and (device.mac_address or device.hostname))
                        )
                        if should_reclassify:
                            vlan_for_check = data.get('vlan_id')
                            if vlan_for_check is None and device.vlan is not None:
                                try:
                                    vlan_for_check = int(device.vlan)
                                except (ValueError, TypeError):
                                    pass
                            new_type = _detect_device_type(ip, mac=device.mac_address, vlan_id=vlan_for_check, hostname=device.hostname)
                            if new_type != device.device_type:
                                device.device_type = new_type
                    else:
                        is_known = ip in WHITELIST_IPS
                        vlan_val = data.get('vlan_id')
                        if vlan_val is None:
                            vlan_val = _get_vlan_from_ip(ip)
                        device_type = _detect_device_type(ip, mac=data.get('mac'), vlan_id=vlan_val, hostname=data.get('hostname'))
                        # Verificăm dacă există deja un dispozitiv cu același MAC (potential duplicat)
                        new_mac = data.get('mac')
                        if new_mac and not _is_randomized_mac(new_mac) and device_type not in _FIXED_DEVICE_TYPES:
                            existing_with_mac = NetworkDevice.query.filter(
                                NetworkDevice.mac_address == new_mac,
                                NetworkDevice.ip_address != ip,
                            ).first()
                            if existing_with_mac:
                                _trigger_deduplication = True
                        device = NetworkDevice(
                            ip_address=ip,
                            mac_address=data.get('mac'),
                            hostname=data.get('hostname'),
                            device_type=device_type,
                            first_seen=data['last_seen'],
                            last_seen=data['last_seen'],
                            total_packets=data['packets'],
                            total_bytes=data['bytes'],
                            is_known=is_known,
                            vlan=str(vlan_val) if vlan_val is not None else None,
                        )
                        db.session.add(device)
                        # Alertă pentru dispozitiv nou necunoscut
                        if not is_known:
                            alert = Alert(
                                alert_type='new_device',
                                source_ip=ip,
                                message=f'Dispozitiv nou detectat în rețea: {ip}',
                                severity='medium',
                                status='active',
                            )
                            db.session.add(alert)
                            log = SecurityLog(
                                event_type='new_device',
                                source_ip=ip,
                                message=f'Dispozitiv nou necunoscut detectat: {ip}',
                                severity='warning',
                            )
                            db.session.add(log)
                except Exception as e:
                    print(f"[Sniffer] Eroare la actualizarea dispozitivului {ip}: {e}")
                    db.session.rollback()
                    continue

            db.session.commit()

            # Deduplicăm dacă am detectat un nou dispozitiv cu MAC deja existent
            if _trigger_deduplication:
                _deduplicate_devices(app)
    except Exception as e:
        print(f"[Sniffer] Eroare la flush dispozitive: {e}")

    _last_device_flush = time.monotonic()


def _deduplicate_all_mobile_devices(app):
    """Deduplicare completă pentru dispozitivele mobile — inclusiv MAC-uri randomizate.
    Când un telefon se mută între AP-uri, primește IP nou dar același MAC.
    Păstrăm intrarea cu last_seen cel mai recent și ștergem restul.
    """
    global _dedup_running
    if _dedup_running:
        return 0
    _dedup_running = True
    from app.models import NetworkDevice
    from app import db
    from sqlalchemy import func
    try:
        with app.app_context():
            try:
                dup_macs = db.session.query(NetworkDevice.mac_address)\
                    .filter(NetworkDevice.mac_address.isnot(None))\
                    .filter(NetworkDevice.device_type == 'mobile')\
                    .group_by(NetworkDevice.mac_address)\
                    .having(func.count(NetworkDevice.id) > 1).all()
                deleted = 0
                for (mac,) in dup_macs:
                    devices = NetworkDevice.query.filter_by(mac_address=mac)\
                        .order_by(NetworkDevice.last_seen.desc()).all()
                    if len(devices) < 2:
                        continue
                    primary = devices[0]
                    for dup in devices[1:]:
                        primary.total_packets = (primary.total_packets or 0) + (dup.total_packets or 0)
                        primary.total_bytes = (primary.total_bytes or 0) + (dup.total_bytes or 0)
                        if not primary.hostname and dup.hostname:
                            primary.hostname = dup.hostname
                        if not primary.first_seen or (dup.first_seen and dup.first_seen < primary.first_seen):
                            primary.first_seen = dup.first_seen
                        db.session.delete(dup)
                        deleted += 1
                        print(f"[Dedup] Șters duplicat: {dup.ip_address} → {primary.ip_address} (MAC: {mac})")
                if deleted > 0:
                    db.session.commit()
                    print(f"[Dedup] Total șterse: {deleted} duplicate mobile.")
                return deleted
            except Exception as e:
                print(f"[Dedup] Eroare: {e}")
                db.session.rollback()
                return 0
    finally:
        _dedup_running = False


def _maybe_flush_devices(app):
    """Apelează flush-ul dacă a trecut intervalul de timp."""
    global _last_device_flush, _last_mobile_cleanup, _last_dedup_cleanup
    if time.monotonic() - _last_device_flush >= _DEVICE_FLUSH_INTERVAL:
        _flush_device_buffer(app)
    # Curățăm dispozitivele mobile inactive cu MAC randomizat o dată la 6 ore
    if time.monotonic() - _last_mobile_cleanup >= _MOBILE_CLEANUP_INTERVAL:
        _cleanup_inactive_mobile_devices(app, ttl_hours=24)
        _last_mobile_cleanup = time.monotonic()
    # Deduplicăm dispozitivele mobile la fiecare 5 minute (DHCP lease = 10 min)
    if time.monotonic() - _last_dedup_cleanup >= _DEDUP_CLEANUP_INTERVAL:
        _last_dedup_cleanup = time.monotonic()
        t = threading.Thread(target=_deduplicate_all_mobile_devices, args=(app,), daemon=True)
        t.start()


def _update_stats(packet_info):
    """Actualizează statisticile globale cu informațiile unui pachet."""
    with _stats_lock:
        traffic_stats['total_packets'] += 1
        traffic_stats['bytes_total'] += packet_info.get('size', 0)
        traffic_stats['protocols'][packet_info.get('protocol', 'Unknown')] += 1

        src = packet_info.get('src_ip', '')
        dst = packet_info.get('dst_ip', '')
        if src:
            traffic_stats['top_sources'][src] += 1
        if dst:
            traffic_stats['top_destinations'][dst] += 1

        # Păstrăm doar ultimele 100 de pachete
        traffic_stats['last_packets'].append({
            'timestamp': packet_info.get('timestamp', ''),
            'src_ip': src,
            'dst_ip': dst,
            'protocol': packet_info.get('protocol', ''),
            'src_port': packet_info.get('src_port'),
            'dst_port': packet_info.get('dst_port'),
            'size': packet_info.get('size', 0),
        })
        if len(traffic_stats['last_packets']) > 100:
            traffic_stats['last_packets'].pop(0)


def _process_packet(packet_info, app):
    """Procesează un pachet: actualizează statisticile și analizează pentru IDS."""
    _update_stats(packet_info)

    # Actualizăm buffer-ul de dispozitive pentru IP-ul sursă
    src_ip = packet_info.get('src_ip', '')
    src_mac = packet_info.get('src_mac')
    size = packet_info.get('size', 0)
    vlan_id = packet_info.get('vlan_id')
    dhcp_hostname = packet_info.get('dhcp_hostname')
    _update_device_buffer(src_ip, src_mac, size, vlan_id=vlan_id, hostname=dhcp_hostname)

    # Actualizăm hint-ul de trafic mobil pe baza portului destinație
    dst_port = packet_info.get('dst_port')
    if src_ip and dst_port in MOBILE_INDICATOR_PORTS:
        _update_mobile_traffic_hint(src_ip, dst_port)

    # Flush periodic la baza de date (non-blocant când nu e momentul)
    _maybe_flush_devices(app)

    # Actualizăm conexiunile per IP sursă
    dns_query = packet_info.get('dns_query')
    dst_ip = packet_info.get('dst_ip', '')

    if dns_query and src_ip:
        # Stocăm în cache DNS: dst_ip -> hostname (pt pachete ulterioare HTTPS)
        with _dns_cache_lock:
            _dns_cache[dst_ip] = dns_query
        _update_connection(src_ip, dns_query, size)
    elif src_ip and dst_ip:
        # Încearcă să găsim hostname din cache DNS
        with _dns_cache_lock:
            hostname = _dns_cache.get(dst_ip)
        if hostname:
            _update_connection(src_ip, hostname, size)

    _maybe_flush_connections(app)

    # Analizăm pachetul cu detectorul IDS
    with app.app_context():
        from app.ids.detector import detector
        detector.analyze_packet(packet_info)


def _real_sniffer(app, interface=None):
    """
    Capturează pachete reale de rețea folosind Scapy.
    Necesită privilegii root/administrator.
    """
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DHCP, BOOTP
    except ImportError:
        print("[Sniffer] Scapy nu este disponibil. Treceți la modul simulat.")
        return

    def process_scapy_packet(pkt):
        """Callback pentru fiecare pachet capturat de Scapy."""
        if not _running:
            return

        from scapy.all import Ether, Dot1Q
        packet_info = {
            'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': '',
            'dst_ip': '',
            'protocol': 'Unknown',
            'src_port': None,
            'dst_port': None,
            'size': len(pkt),
            'src_mac': pkt[Ether].src if pkt.haslayer(Ether) else None,
            'vlan_id': pkt[Dot1Q].vlan if pkt.haslayer(Dot1Q) else None,
        }

        # Extragem informații din stratul IP
        if pkt.haslayer(IP):
            packet_info['src_ip'] = pkt[IP].src
            packet_info['dst_ip'] = pkt[IP].dst

            if pkt.haslayer(TCP):
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = pkt[TCP].sport
                packet_info['dst_port'] = pkt[TCP].dport
                # Detectăm HTTP/HTTPS pe baza portului
                if pkt[TCP].dport in (80, 8080) or pkt[TCP].sport in (80, 8080):
                    packet_info['protocol'] = 'HTTP'
                elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                    packet_info['protocol'] = 'HTTPS'

            elif pkt.haslayer(UDP):
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = pkt[UDP].sport
                packet_info['dst_port'] = pkt[UDP].dport
                # Detectăm DNS pe portul 53
                if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                    packet_info['protocol'] = 'DNS'
                    # Extrage hostname din query DNS
                    try:
                        if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qd:
                            qname = pkt[DNS].qd.qname
                            if isinstance(qname, bytes):
                                qname = qname.decode('utf-8', errors='ignore')
                            packet_info['dns_query'] = qname.rstrip('.')
                    except Exception:
                        pass
                # Detectăm DHCP pe porturile 67/68
                elif pkt[UDP].dport in (67, 68) or pkt[UDP].sport in (67, 68):
                    packet_info['protocol'] = 'DHCP'
                    try:
                        if pkt.haslayer(BOOTP) and pkt.haslayer(DHCP):
                            # Extrage hostname din DHCP Option 12
                            for opt in pkt[DHCP].options:
                                if isinstance(opt, tuple) and opt[0] == 'hostname':
                                    dhcp_hostname = opt[1]
                                    if isinstance(dhcp_hostname, bytes):
                                        dhcp_hostname = dhcp_hostname.decode('utf-8', errors='ignore')
                                    dhcp_hostname = dhcp_hostname.strip()
                                    packet_info['dhcp_hostname'] = dhcp_hostname
                                    # Mapăm IP-ul clientului la hostname în cache
                                    # yiaddr = IP alocat de server; ciaddr = IP curent al clientului
                                    client_ip = pkt[BOOTP].yiaddr
                                    if not client_ip or client_ip == '0.0.0.0':
                                        client_ip = pkt[BOOTP].ciaddr
                                    if not client_ip or client_ip == '0.0.0.0':
                                        client_ip = pkt[IP].src if pkt.haslayer(IP) else None
                                    if client_ip and client_ip != '0.0.0.0':
                                        with _device_hostname_cache_lock:
                                            _device_hostname_cache[client_ip] = dhcp_hostname
                                    break
                    except Exception:
                        pass

            elif pkt.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'

        elif pkt.haslayer(ARP):
            packet_info['protocol'] = 'ARP'
            packet_info['src_ip'] = pkt[ARP].psrc
            packet_info['dst_ip'] = pkt[ARP].pdst

        _process_packet(packet_info, app)

    print(f"[Sniffer] Pornesc captura pe interfața: {interface or 'auto'}")
    sniff(
        iface=interface,
        prn=process_scapy_packet,
        store=False,
        stop_filter=lambda _: not _running
    )


def _simulated_sniffer(app):
    """
    Generează trafic simulat pentru testare pe sisteme fără Scapy sau drepturi root.
    Util pentru demonstrații și dezvoltare.
    """
    # IP-uri simulate în rețeaua școlii
    school_ips = [
        '192.168.1.' + str(i) for i in range(10, 50)
    ]
    external_ips = [
        '8.8.8.8', '1.1.1.1', '185.60.216.35',
        '104.26.10.228', '172.67.68.228'
    ]
    protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS']
    ports = [80, 443, 22, 53, 8080, 3306, 3389, 25, 110]

    # Generăm ocazional trafic suspect pentru demonstrație
    suspicious_counter = 0

    print("[Sniffer] Modul simulat activat. Generez trafic fictiv pentru demonstrație.")

    while _running:
        suspicious_counter += 1

        # Generăm un pachet normal
        src = random.choice(school_ips + external_ips)
        dst = random.choice(school_ips + external_ips)
        while dst == src:
            dst = random.choice(school_ips + external_ips)

        proto = random.choice(protocols)
        sport = random.randint(1024, 65535)
        dport = random.choice(ports)
        size = random.randint(64, 1500)

        packet_info = {
            'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': src,
            'dst_ip': dst,
            'protocol': proto,
            'src_port': sport,
            'dst_port': dport,
            'size': size,
        }
        _process_packet(packet_info, app)

        # La fiecare 200 pachete, simulăm un atac de port scanning
        if suspicious_counter % 200 == 0:
            attacker_ip = '10.0.0.' + str(random.randint(1, 20))
            target_ip = random.choice(school_ips)
            print(f"[Sniffer] Simulez port scan de la {attacker_ip}")
            for scan_port in random.sample(range(1, 1024), 20):
                scan_info = {
                    'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                    'src_ip': attacker_ip,
                    'dst_ip': target_ip,
                    'protocol': 'TCP',
                    'src_port': random.randint(1024, 65535),
                    'dst_port': scan_port,
                    'size': 40,
                }
                _process_packet(scan_info, app)

        # La fiecare 300 pachete, simulăm un atac brute force pe SSH
        if suspicious_counter % 300 == 0:
            brute_ip = '172.16.0.' + str(random.randint(1, 10))
            target_ip = random.choice(school_ips)
            print(f"[Sniffer] Simulez brute force SSH de la {brute_ip}")
            for _ in range(15):
                brute_info = {
                    'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                    'src_ip': brute_ip,
                    'dst_ip': target_ip,
                    'protocol': 'TCP',
                    'src_port': random.randint(1024, 65535),
                    'dst_port': 22,
                    'size': 60,
                }
                _process_packet(brute_info, app)

        time.sleep(0.1)  # 10 pachete pe secundă în modul simulat


def _tzsp_sniffer(app):
    """
    Ascultă pachete TZSP (TaZmen Sniffer Protocol) pe UDP trimise de routerul MikroTik.
    Decodifică antetul TZSP, extrage frame-ul Ethernet original și îl procesează cu Scapy.
    Nu necesită privilegii root (portul 37008 > 1024).
    """
    try:
        from scapy.all import Ether, IP, TCP, UDP as ScapyUDP, ICMP, ARP, DNS, Dot1Q, DHCP, BOOTP
    except ImportError:
        print("[Sniffer] Scapy nu este disponibil. Modul TZSP necesită Scapy.")
        return

    listen_addr = app.config.get('TZSP_LISTEN_ADDRESS', '0.0.0.0')
    listen_port = app.config.get('TZSP_PORT', 37008)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(1.0)
    try:
        sock.bind((listen_addr, listen_port))
    except OSError as e:
        print(f"[Sniffer] Nu pot lega socket-ul TZSP la {listen_addr}:{listen_port}: {e}")
        sock.close()
        return

    print(f"[Sniffer] Modul TZSP activat. Ascult pachete MikroTik pe {listen_addr}:{listen_port}")

    # Constante TZSP
    TZSP_TAG_END = 0x01
    TZSP_ENCAP_ETHERNET = 0x0001

    try:
        while _running:
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as e:
                if _running:
                    print(f"[Sniffer] Eroare socket TZSP: {e}")
                break

            try:
                # Antet TZSP: Version (1) + Type (1) + Encapsulated Protocol (2)
                if len(data) < 4:
                    continue

                version = data[0]
                pkt_type = data[1]
                encap_proto = (data[2] << 8) | data[3]

                if version != 1 or pkt_type != 0:
                    # Ignorăm pachetele care nu sunt tip 0 (packet for capture)
                    continue

                if encap_proto != TZSP_ENCAP_ETHERNET:
                    # Suportăm doar Ethernet encapsulat
                    continue

                # Parcurgem câmpurile tagged până la TAG_END (0x01)
                offset = 4
                while offset < len(data):
                    tag = data[offset]
                    offset += 1
                    if tag == TZSP_TAG_END:
                        # S-a găsit TAG_END; restul este frame-ul original
                        break
                    if tag == 0x00:
                        # TAG_PADDING - fără date
                        continue
                    # Celelalte tag-uri au un byte lungime urmat de date
                    if offset >= len(data):
                        break
                    tag_len = data[offset]
                    offset += 1 + tag_len  # sărim peste date
                else:
                    # Nu s-a găsit TAG_END valid
                    continue

                raw_frame = data[offset:]
                if not raw_frame:
                    continue

                pkt = Ether(raw_frame)

                packet_info = {
                    'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                    'src_ip': '',
                    'dst_ip': '',
                    'protocol': 'Unknown',
                    'src_port': None,
                    'dst_port': None,
                    'size': len(raw_frame),
                    'src_mac': pkt.src if pkt.haslayer(Ether) else None,
                    'vlan_id': pkt[Dot1Q].vlan if pkt.haslayer(Dot1Q) else None,
                }

                if pkt.haslayer(IP):
                    packet_info['src_ip'] = pkt[IP].src
                    packet_info['dst_ip'] = pkt[IP].dst

                    if pkt.haslayer(TCP):
                        packet_info['protocol'] = 'TCP'
                        packet_info['src_port'] = pkt[TCP].sport
                        packet_info['dst_port'] = pkt[TCP].dport
                        if pkt[TCP].dport in (80, 8080) or pkt[TCP].sport in (80, 8080):
                            packet_info['protocol'] = 'HTTP'
                        elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                            packet_info['protocol'] = 'HTTPS'

                    elif pkt.haslayer(ScapyUDP):
                        packet_info['protocol'] = 'UDP'
                        packet_info['src_port'] = pkt[ScapyUDP].sport
                        packet_info['dst_port'] = pkt[ScapyUDP].dport
                        if pkt[ScapyUDP].dport == 53 or pkt[ScapyUDP].sport == 53:
                            packet_info['protocol'] = 'DNS'
                            # Extrage hostname din query DNS
                            try:
                                if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qd:
                                    qname = pkt[DNS].qd.qname
                                    if isinstance(qname, bytes):
                                        qname = qname.decode('utf-8', errors='ignore')
                                    packet_info['dns_query'] = qname.rstrip('.')
                            except Exception:
                                pass
                        # Detectăm DHCP pe porturile 67/68
                        elif pkt[ScapyUDP].dport in (67, 68) or pkt[ScapyUDP].sport in (67, 68):
                            packet_info['protocol'] = 'DHCP'
                            try:
                                if pkt.haslayer(BOOTP) and pkt.haslayer(DHCP):
                                    # Extrage hostname din DHCP Option 12
                                    for opt in pkt[DHCP].options:
                                        if isinstance(opt, tuple) and opt[0] == 'hostname':
                                            dhcp_hostname = opt[1]
                                            if isinstance(dhcp_hostname, bytes):
                                                dhcp_hostname = dhcp_hostname.decode('utf-8', errors='ignore')
                                            dhcp_hostname = dhcp_hostname.strip()
                                            packet_info['dhcp_hostname'] = dhcp_hostname
                                            # Mapăm IP-ul clientului la hostname în cache
                                            # yiaddr = IP alocat de server; ciaddr = IP curent al clientului
                                            client_ip = pkt[BOOTP].yiaddr
                                            if not client_ip or client_ip == '0.0.0.0':
                                                client_ip = pkt[BOOTP].ciaddr
                                            if not client_ip or client_ip == '0.0.0.0':
                                                client_ip = pkt[IP].src if pkt.haslayer(IP) else None
                                            if client_ip and client_ip != '0.0.0.0':
                                                with _device_hostname_cache_lock:
                                                    _device_hostname_cache[client_ip] = dhcp_hostname
                                            break
                            except Exception:
                                pass

                    elif pkt.haslayer(ICMP):
                        packet_info['protocol'] = 'ICMP'

                elif pkt.haslayer(ARP):
                    packet_info['protocol'] = 'ARP'
                    packet_info['src_ip'] = pkt[ARP].psrc
                    packet_info['dst_ip'] = pkt[ARP].pdst

                _process_packet(packet_info, app)

            except Exception as e:
                print(f"[Sniffer] Pachet TZSP malformat, ignorat: {e}")
                continue
    finally:
        sock.close()


def _fix_device_types(app):
    """Reclasifică dispozitivele cu tip greșit folosind _detect_device_type()."""
    from app.models import NetworkDevice
    from app import db

    try:
        with app.app_context():
            devices = NetworkDevice.query.all()
            count = 0
            for device in devices:
                vlan_id = None
                if device.vlan is not None:
                    try:
                        vlan_id = int(device.vlan)
                    except (ValueError, TypeError):
                        pass
                correct_type = _detect_device_type(device.ip_address, mac=device.mac_address, vlan_id=vlan_id, hostname=device.hostname)
                if correct_type != device.device_type:
                    print(f"[Sniffer] Dispozitiv reclasificat: {device.ip_address} {device.device_type} → {correct_type}")
                    device.device_type = correct_type
                    count += 1
            if count > 0:
                db.session.commit()
                print(f"[Sniffer] Total dispozitive reclasificate: {count}")
            else:
                print("[Sniffer] Nicio reclasificare necesară.")
    except Exception as e:
        print(f"[Sniffer] Eroare la reclasificarea dispozitivelor: {e}")
        try:
            with app.app_context():
                db.session.rollback()
        except Exception as rollback_err:
            print(f"[Sniffer] Eroare la rollback (tipuri): {rollback_err}")


def _fix_device_vlans(app):
    """Setează VLAN-ul pentru dispozitivele din DB care nu au VLAN, pe baza mapării IP→VLAN."""
    from app.models import NetworkDevice
    from app import db

    try:
        with app.app_context():
            devices = NetworkDevice.query.filter_by(vlan=None).all()
            count = 0
            for device in devices:
                vlan_id = _get_vlan_from_ip(device.ip_address)
                if vlan_id is not None:
                    print(f"[Sniffer] VLAN setat pentru {device.ip_address}: VLAN {vlan_id}")
                    device.vlan = str(vlan_id)
                    count += 1
            if count > 0:
                db.session.commit()
                print(f"[Sniffer] Total dispozitive cu VLAN setat: {count}")
    except Exception as e:
        print(f"[Sniffer] Eroare la setarea VLAN-urilor: {e}")
        try:
            with app.app_context():
                db.session.rollback()
        except Exception as rollback_err:
            print(f"[Sniffer] Eroare la rollback (VLAN): {rollback_err}")


def _deduplicate_devices(app):
    """Găsește și consolidează dispozitivele duplicate (același MAC, IP-uri diferite).

    Un telefon care se plimbă prin școală primește IP-uri diferite de la AP-uri diferite,
    dar MAC-ul rămâne același pe aceeași rețea. Această funcție consolidează toate
    intrările cu același MAC într-una singură (cea mai veche), sumând statisticile.

    Exclude din deduplicare:
    - MAC-uri None sau goale
    - MAC-uri randomizate (LAA bit setat)
    - Dispozitive din _FIXED_DEVICE_TYPES (camere, routere, switch-uri, servere, AP-uri)
    """
    from app.models import NetworkDevice
    from app import db
    from datetime import datetime

    try:
        with app.app_context():
            # Găsim toate dispozitivele cu MAC non-null
            devices = NetworkDevice.query.filter(
                NetworkDevice.mac_address.isnot(None)
            ).all()

            # Grupăm după MAC, excludem randomizate și infrastructură fixă
            mac_groups = {}
            for device in devices:
                mac = device.mac_address
                if not mac or _is_randomized_mac(mac):
                    continue
                if device.device_type in _FIXED_DEVICE_TYPES:
                    continue
                if mac not in mac_groups:
                    mac_groups[mac] = []
                mac_groups[mac].append(device)

            # Pentru fiecare grup cu duplicate, consolidăm datele
            total_deleted = 0
            for mac, group in mac_groups.items():
                if len(group) < 2:
                    continue

                # Sortăm: cel cu first_seen cel mai vechi primul (None → cel mai vechi)
                group.sort(key=lambda d: d.first_seen if d.first_seen is not None else datetime(1970, 1, 1))
                primary = group[0]  # păstrăm acesta
                duplicates = group[1:]

                # Consolidăm datele din duplicate în dispozitivul principal
                for dup in duplicates:
                    primary.total_packets = (primary.total_packets or 0) + (dup.total_packets or 0)
                    primary.total_bytes = (primary.total_bytes or 0) + (dup.total_bytes or 0)
                    if dup.last_seen and (not primary.last_seen or dup.last_seen > primary.last_seen):
                        primary.last_seen = dup.last_seen
                    if not primary.hostname and dup.hostname:
                        primary.hostname = dup.hostname

                    db.session.delete(dup)
                    total_deleted += 1

            if total_deleted > 0:
                db.session.commit()
                print(f"[Sniffer] Deduplicare: {total_deleted} dispozitive duplicate eliminate.")
            else:
                print("[Sniffer] Deduplicare: niciun duplicat găsit.")

            return total_deleted
    except Exception as e:
        print(f"[Sniffer] Eroare la deduplicarea dispozitivelor: {e}")
        try:
            with app.app_context():
                db.session.rollback()
        except Exception as rollback_err:
            print(f"[Sniffer] Eroare la rollback (deduplicare): {rollback_err}")
        return 0


def _cleanup_inactive_mobile_devices(app, ttl_hours=24):
    """Șterge dispozitivele mobile cu MAC randomizat care nu au mai generat trafic în ultimele ttl_hours ore.

    Telefoanele moderne folosesc MAC randomizat (LAA bit), ceea ce face imposibilă
    deduplicarea pe baza MAC-ului. În schimb, eliminăm intrările vechi inactive.

    Args:
        app: Instanța aplicației Flask.
        ttl_hours: Numărul de ore după care un dispozitiv inactiv este șters. Default: 24.

    Returns:
        int: Numărul de dispozitive șterse.
    """
    from app.models import NetworkDevice
    from app import db
    from datetime import datetime, timedelta

    try:
        with app.app_context():
            cutoff = datetime.utcnow() - timedelta(hours=ttl_hours)
            devices = NetworkDevice.query.filter_by(device_type='mobile').all()

            to_delete = []
            for device in devices:
                if not _is_randomized_mac(device.mac_address):
                    continue
                if device.last_seen is not None and device.last_seen < cutoff:
                    to_delete.append(device)

            total_deleted = len(to_delete)
            for device in to_delete:
                db.session.delete(device)

            if total_deleted > 0:
                db.session.commit()
                print(f"[Sniffer] Curățare mobile inactive: {total_deleted} dispozitive cu MAC randomizat șterse (TTL={ttl_hours}h).")
            else:
                print("[Sniffer] Curățare mobile inactive: niciun dispozitiv inactiv găsit.")

            return total_deleted
    except Exception as e:
        print(f"[Sniffer] Eroare la curățarea dispozitivelor mobile inactive: {e}")
        try:
            with app.app_context():
                db.session.rollback()
        except Exception as rollback_err:
            print(f"[Sniffer] Eroare la rollback (curățare mobile): {rollback_err}")
        return 0


def start_sniffer(app):
    """
    Pornește snifferul de rețea într-un thread separat.
    Alege automat între modul real (Scapy) și modul simulat.
    """
    global _running, _sniffer_thread

    if _running:
        print("[Sniffer] Snifferul este deja pornit.")
        return

    _running = True

    # Reclasificăm dispozitivele cu tip greșit și setăm VLAN-urile la pornire
    _fix_device_types(app)
    _fix_device_vlans(app)
    # Deduplicăm dispozitivele cu același MAC și IP-uri diferite la pornire
    _deduplicate_devices(app)
    # Deduplicăm dispozitivele mobile inclusiv MAC-uri randomizate la pornire
    _deduplicate_all_mobile_devices(app)
    # Ștergem dispozitivele mobile inactive cu MAC randomizat la pornire
    _cleanup_inactive_mobile_devices(app, ttl_hours=24)

    # Înregistrăm callback-ul pentru salvarea alertelor în baza de date
    with app.app_context():
        from app.ids.detector import detector
        from app.models import Alert, SecurityLog, NetworkDevice
        from app import db

        def save_alert(alert_data):
            """Salvează alerta în baza de date și trimite notificare Telegram."""
            with app.app_context():
                try:
                    alert = Alert(
                        alert_type=alert_data['alert_type'],
                        source_ip=alert_data['source_ip'],
                        destination_ip=alert_data.get('destination_ip'),
                        port=alert_data.get('port'),
                        message=alert_data['message'],
                        severity=alert_data['severity'],
                        status='active'
                    )
                    db.session.add(alert)

                    # Salvăm și în loguri
                    log = SecurityLog(
                        event_type='alert_generated',
                        source_ip=alert_data['source_ip'],
                        destination_ip=alert_data.get('destination_ip'),
                        port=alert_data.get('port'),
                        message=alert_data['message'],
                        severity=alert_data['severity'],
                    )
                    db.session.add(log)
                    db.session.commit()
                    print(f"[IDS] Alertă salvată: {alert_data['alert_type']} de la {alert_data['source_ip']}")

                    # Trimitem notificare Telegram (non-blocant)
                    from app.notifications.telegram import send_alert_notification
                    send_alert_notification(alert_data, app.config)
                except Exception as e:
                    print(f"[IDS] Eroare la salvarea alertei: {e}")
                    db.session.rollback()

        # Adăugăm callback-ul o singură dată
        if not detector.has_callbacks():
            detector.add_alert_callback(save_alert)

    # Determinăm modul de funcționare
    # SNIFFER_MODE are prioritate față de SIMULATION_MODE (compatibilitate inversă)
    sniffer_mode = app.config.get('SNIFFER_MODE', 'simulated')
    simulation_mode = app.config.get('SIMULATION_MODE', True)
    interface = app.config.get('NETWORK_INTERFACE')

    # Dacă SNIFFER_MODE nu a fost setat explicit prin variabila de mediu,
    # folosim SIMULATION_MODE pentru compatibilitate inversă
    if sniffer_mode == 'simulated' and not simulation_mode:
        sniffer_mode = 'interface'

    if sniffer_mode == 'tzsp':
        target_func = lambda: _tzsp_sniffer(app)
    elif sniffer_mode == 'interface':
        target_func = lambda: _real_sniffer(app, interface)
    else:
        target_func = lambda: _simulated_sniffer(app)

    _sniffer_thread = threading.Thread(target=target_func, daemon=True)
    _sniffer_thread.start()
    print(f"[Sniffer] Thread pornit în modul: {sniffer_mode}")


def stop_sniffer():
    """Oprește snifferul de rețea."""
    global _running
    _running = False
    print("[Sniffer] Sniffer oprit.")


def get_stats():
    """Returnează statisticile curente ale traficului."""
    with _stats_lock:
        # Returnăm o copie pentru thread safety
        return {
            'total_packets': traffic_stats['total_packets'],
            'protocols': dict(traffic_stats['protocols']),
            'top_sources': dict(
                sorted(traffic_stats['top_sources'].items(),
                       key=lambda x: x[1], reverse=True)[:10]
            ),
            'top_destinations': dict(
                sorted(traffic_stats['top_destinations'].items(),
                       key=lambda x: x[1], reverse=True)[:10]
            ),
            'bytes_total': traffic_stats['bytes_total'],
            'last_packets': traffic_stats['last_packets'][-20:],
            'start_time': traffic_stats['start_time'],
        }
