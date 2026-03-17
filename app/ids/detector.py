"""
Modulul de detectare a intruziunilor (IDS - Intrusion Detection System).
Analizează traficul capturat și detectează comportamente suspecte.
"""
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from app.ids.rules import (
    PORT_SCAN_RULES, BRUTE_FORCE_RULES,
    HIGH_TRAFFIC_RULES, ARP_RULES, WHITELIST_IPS,
    DNS_TUNNELING_RULES, DHCP_RULES, PACKET_FLOOD_RULES,
    INSECURE_PROTOCOL_RULES, SYN_FLOOD_RULES,
)

logger = logging.getLogger(__name__)

# Lungimea maximă a unui query DNS afișat în mesajele de alertă
_DNS_QUERY_MAX_DISPLAY_LEN = 80
# Mulțimile de caractere hex/base64 folosite la detectarea DNS tunneling
_HEX_CHARS = frozenset('0123456789abcdefABCDEF')
_B64_CHARS = frozenset(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
)

# Cache pentru lista albă personalizată (evită citirea JSON la fiecare pachet)
_whitelist_cache = None
_whitelist_cache_time = 0.0
_WHITELIST_CACHE_TTL = 60  # secunde

# Cache pentru IP-urile blocate (evită interogarea DB la fiecare pachet)
_blocked_cache = None
_blocked_cache_time = 0.0
_BLOCKED_CACHE_TTL = 60  # secunde

# Cache pentru MAC-urile blocate (evită interogarea DB la fiecare pachet)
_blocked_mac_cache = None
_blocked_mac_cache_time = 0.0

# Cache pentru hostname-urile blocate (evită interogarea DB la fiecare pachet)
_blocked_hostname_cache = None
_blocked_hostname_cache_time = 0.0


def invalidate_whitelist_cache():
    """Invalidează cache-ul listei albe (apelat după fiecare modificare a JSON-ului)."""
    global _whitelist_cache
    _whitelist_cache = None


def _is_randomized_mac(mac: str) -> bool:
    """Returnează True dacă MAC-ul pare a fi randomizat/privat (bitul U/L setat).

    Adresele MAC locale administrate (bitul U/L, bitul 1 al primului octet = 1) sunt de obicei
    generate aleator de sistemele de operare moderne pentru protecția vieții private.
    """
    try:
        first_octet = int(mac.split(':')[0], 16)
        # Bitul 1 (valoare 2) din primul octet indică adresă administrată local
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


class IntrusionDetector:
    """
    Clasa principală pentru detectarea intruziunilor.
    Menține statistici în memorie și generează alerte.
    """

    def __init__(self, app=None):
        self.app = app
        # Dicționar: ip -> deque de (timestamp, port) pentru detectarea port scan
        self._port_scan_tracker = defaultdict(deque)
        # Dicționar: ip -> deque de timestamp-uri pentru detectarea brute force
        self._brute_force_tracker = defaultdict(lambda: defaultdict(deque))
        # Dicționar: ip -> deque de (timestamp, bytes) pentru trafic anormal
        self._traffic_tracker = defaultdict(deque)
        # Dicționar: ip -> deque de timestamp-uri pentru ARP
        self._arp_tracker = defaultdict(deque)
        # Dicționar: ip -> deque de (timestamp, query) pentru DNS tunneling
        self._dns_tracker = defaultdict(deque)
        # Dicționar: ip -> deque de timestamp-uri pentru packet flood
        self._packet_flood_tracker = defaultdict(deque)
        # Dicționar: ip -> {dst_port -> deque} pentru SYN flood
        self._syn_flood_tracker = defaultdict(lambda: defaultdict(deque))
        # Dicționar: (src_ip, port) -> last_alert_time pentru protocol nesecurizat
        self._insecure_protocol_cooldown = {}
        # Dicționar: ip -> last_alert_time pentru DHCP spoofing cooldown
        self._dhcp_spoof_cooldown = {}
        # Dicționar: ip -> last_alert_time pentru blocked_ip_active (5 min cooldown)
        self._blocked_ip_alert_cooldown = {}
        # Dicționar: mac -> last_alert_time pentru blocked_mac_active (5 min cooldown)
        self._blocked_mac_alert_cooldown = {}
        # Dicționar: ip -> last_auto_block_time pentru auto-block (5 min cooldown)
        self._auto_block_cooldown = {}
        # Callback pentru salvarea alertelor
        self._alert_callbacks = []

    def add_alert_callback(self, callback):
        """Adaugă un callback care este apelat când se generează o alertă."""
        self._alert_callbacks.append(callback)

    def has_callbacks(self):
        """Verifică dacă există callback-uri înregistrate."""
        return len(self._alert_callbacks) > 0

    def _fire_alert(self, alert_type, source_ip, message, severity='medium',
                    destination_ip=None, port=None):
        """Declanșează o alertă prin toate callback-urile înregistrate."""
        alert_data = {
            'alert_type': alert_type,
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'port': port,
            'message': message,
            'severity': severity,
            'timestamp': datetime.now(timezone.utc),
        }
        for callback in self._alert_callbacks:
            try:
                callback(alert_data)
            except Exception as e:
                print(f"[IDS] Eroare în callback: {e}")
        # Auto-block după ce alerta a fost salvată prin callbacks
        self._maybe_auto_block(source_ip, severity, alert_type, message)

    def _maybe_auto_block(self, source_ip, severity, alert_type, reason):
        """Blochează automat IP-ul și/sau MAC-ul dacă severitatea o cere și dacă nu este whitelisted."""
        try:
            from flask import current_app
            cfg = current_app.config
        except Exception:
            return

        if not cfg.get('AUTO_BLOCK_ENABLED', True):
            return

        auto_block_severities = cfg.get('AUTO_BLOCK_SEVERITY', ['critical', 'high'])
        if severity not in auto_block_severities:
            return

        if self._is_whitelisted(source_ip):
            return

        # Cooldown: nu bloca același IP mai des de o dată la 5 minute
        current_time = time.time()
        last_block = self._auto_block_cooldown.get(source_ip, 0)
        if current_time - last_block < 300:
            return

        try:
            from app import db
            from app.models import BlockedIP, BlockedMAC, NetworkDevice, SecurityLog

            # Verificăm dacă IP-ul nu este deja blocat
            existing = BlockedIP.query.filter_by(ip_address=source_ip, is_active=True).first()
            if existing:
                return

            # Blocăm IP-ul în baza de date
            blocked = BlockedIP(
                ip_address=source_ip,
                reason=f'Auto-blocat: {alert_type} - {reason}',
                blocked_by='system-auto',
            )
            db.session.add(blocked)

            # Căutăm MAC-ul dispozitivului din NetworkDevice
            device = NetworkDevice.query.filter_by(ip_address=source_ip).first()
            mac_blocked = False
            hostname_blocked = False
            if device and device.mac_address:
                mac = device.mac_address.upper()
                # Blocăm MAC-ul doar dacă nu pare randomizat (bitul U/L)
                if not _is_randomized_mac(mac):
                    existing_mac = BlockedMAC.query.filter_by(mac_address=mac, is_active=True).first()
                    if not existing_mac:
                        blocked_mac = BlockedMAC(
                            mac_address=mac,
                            reason=f'Auto-blocat: {alert_type} - {reason}',
                            blocked_by='system-auto',
                            associated_ip=source_ip,
                        )
                        db.session.add(blocked_mac)
                        mac_blocked = True
                else:
                    # MAC randomizat → blocăm pe hostname dacă există
                    if device.hostname:
                        hostname_lower = device.hostname.lower()
                        from app.models import BlockedHostname
                        existing_hn = BlockedHostname.query.filter_by(
                            hostname=hostname_lower, is_active=True
                        ).first()
                        if not existing_hn:
                            blocked_hn = BlockedHostname(
                                hostname=hostname_lower,
                                reason=f'Auto-blocat: {alert_type} - {reason}',
                                blocked_by='system-auto',
                                associated_ip=source_ip,
                                associated_mac=mac,
                            )
                            db.session.add(blocked_hn)
                            hostname_blocked = True

            # Log de securitate
            log = SecurityLog(
                event_type='auto_block',
                source_ip=source_ip,
                message=(f'IP {source_ip} blocat automat '
                         f'(severitate: {severity}, tip alertă: {alert_type})'
                         + (f'; MAC {device.mac_address} blocat' if mac_blocked else '')
                         + (f'; hostname {device.hostname} blocat' if hostname_blocked else '')),
                severity='warning',
            )
            db.session.add(log)
            db.session.commit()

            # Actualizăm cooldown-ul și invalidăm cache-urile
            self._auto_block_cooldown[source_ip] = current_time
            global _blocked_cache, _blocked_mac_cache, _blocked_hostname_cache
            _blocked_cache = None
            _blocked_mac_cache = None
            _blocked_hostname_cache = None

            print(f"[IDS] IP {source_ip} blocat automat (severitate: {severity})")

            # Dacă MikroTik este conectat, blocăm și pe router
            try:
                mikrotik = getattr(current_app, 'mikrotik_client', None)
                if mikrotik and mikrotik.is_connected():
                    comment = f'Auto-blocat SchoolSec: {alert_type}'
                    if mac_blocked:
                        mikrotik.block_mac_on_router(device.mac_address, comment=comment)
                    elif hostname_blocked:
                        mikrotik.block_hostname_on_router(device.hostname, comment=comment)
                    else:
                        mikrotik.block_ip_on_router(source_ip, comment=comment)
            except Exception as e:
                print(f"[IDS] Eroare auto-block MikroTik pentru {source_ip}: {e}")

        except Exception as e:
            print(f"[IDS] Eroare auto-block {source_ip}: {e}")
            try:
                from app import db
                db.session.rollback()
            except Exception:
                pass

    def _is_whitelisted(self, ip):
        """Verifică dacă IP-ul este în lista albă (builtin + personalizată)."""
        if ip in WHITELIST_IPS:
            return True
        # Verifică lista personalizată din JSON, cu cache de 60 de secunde
        global _whitelist_cache, _whitelist_cache_time
        now = time.time()
        if _whitelist_cache is None or (now - _whitelist_cache_time) > _WHITELIST_CACHE_TTL:
            try:
                from app.routes.settings import _load_custom_whitelist
                _whitelist_cache = {e.get('ip') for e in _load_custom_whitelist()}
                _whitelist_cache_time = now
            except Exception:
                return False
        return ip in _whitelist_cache

    def _is_blocked(self, ip):
        """Verifică dacă IP-ul este blocat în baza de date (cu cache TTL 60s)."""
        global _blocked_cache, _blocked_cache_time
        now = time.time()
        if _blocked_cache is None or (now - _blocked_cache_time) > _BLOCKED_CACHE_TTL:
            try:
                from app.models import BlockedIP
                blocked_ips = BlockedIP.query.filter_by(is_active=True).all()
                _blocked_cache = {b.ip_address for b in blocked_ips}
                _blocked_cache_time = now
            except Exception:
                return False
        return ip in _blocked_cache

    def _is_blocked_mac(self, mac):
        """Verifică dacă MAC-ul este blocat în baza de date (cu cache TTL 60s)."""
        global _blocked_mac_cache, _blocked_mac_cache_time
        now = time.time()
        if _blocked_mac_cache is None or (now - _blocked_mac_cache_time) > _BLOCKED_CACHE_TTL:
            try:
                from app.models import BlockedMAC
                blocked_macs = BlockedMAC.query.filter_by(is_active=True).all()
                _blocked_mac_cache = {b.mac_address.upper() for b in blocked_macs}
                _blocked_mac_cache_time = now
            except Exception:
                return False
        return mac.upper() in (_blocked_mac_cache or set())

    def _is_blocked_hostname(self, hostname):
        """Verifică dacă hostname-ul este blocat în baza de date (cu cache TTL 60s)."""
        if not hostname:
            return False
        global _blocked_hostname_cache, _blocked_hostname_cache_time
        now = time.time()
        if _blocked_hostname_cache is None or (now - _blocked_hostname_cache_time) > _BLOCKED_CACHE_TTL:
            try:
                from app.models import BlockedHostname
                blocked_hostnames = BlockedHostname.query.filter_by(is_active=True).all()
                _blocked_hostname_cache = {b.hostname.lower() for b in blocked_hostnames}
                _blocked_hostname_cache_time = now
            except Exception:
                return False
        return hostname.lower() in (_blocked_hostname_cache or set())

    def _clean_old_entries(self, dq, window_seconds):
        """Elimină intrările mai vechi decât fereastra de timp."""
        cutoff = time.time() - window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def analyze_packet(self, packet_info):
        """
        Analizează informațiile unui pachet și detectează amenințări.
        packet_info este un dicționar cu: src_ip, dst_ip, protocol, src_port, dst_port, size
        Opțional: src_mac — adresa MAC sursă a pachetului
        """
        src_ip = packet_info.get('src_ip', '')
        dst_ip = packet_info.get('dst_ip', '')
        protocol = packet_info.get('protocol', '')
        dst_port = packet_info.get('dst_port')
        size = packet_info.get('size', 0)
        src_mac = packet_info.get('src_mac', '')

        # Nu analizăm IP-urile din lista albă
        if self._is_whitelisted(src_ip):
            return

        current_time = time.time()

        # Verificăm dacă un MAC blocat continuă să trimită trafic
        if src_mac and self._is_blocked_mac(src_mac):
            last_alert = self._blocked_mac_alert_cooldown.get(src_mac, 0)
            if current_time - last_alert >= 300:  # cooldown 5 minute
                self._blocked_mac_alert_cooldown[src_mac] = current_time
                self._fire_alert(
                    alert_type='blocked_mac_active',
                    source_ip=src_ip,
                    message=f"Dispozitiv cu MAC blocat {src_mac} (IP: {src_ip}) continuă să trimită trafic.",
                    severity='critical',
                )
            return  # Nu mai analizăm alte reguli pentru dispozitive blocate pe MAC

        # Verificăm dacă un IP blocat continuă să trimită trafic
        if self._is_blocked(src_ip):
            last_alert = self._blocked_ip_alert_cooldown.get(src_ip, 0)
            if current_time - last_alert >= 300:  # cooldown 5 minute
                self._blocked_ip_alert_cooldown[src_ip] = current_time
                self._fire_alert(
                    alert_type='blocked_ip_active',
                    source_ip=src_ip,
                    message=f"IP blocat {src_ip} continuă să trimită trafic în rețea.",
                    severity='critical',
                )
            return  # Nu mai analizăm alte reguli pentru IP-uri blocate

        # Verificăm port scanning
        if PORT_SCAN_RULES['enabled'] and dst_port and protocol in ('TCP', 'UDP'):
            self._check_port_scan(src_ip, dst_ip, dst_port, current_time)

        # Verificăm brute force pe porturi sensibile
        if BRUTE_FORCE_RULES['enabled'] and dst_port:
            if dst_port in BRUTE_FORCE_RULES['monitored_ports']:
                self._check_brute_force(src_ip, dst_ip, dst_port, current_time)

        # Verificăm volumul de trafic
        if HIGH_TRAFFIC_RULES['enabled'] and size > 0:
            self._check_high_traffic(src_ip, size, current_time)

        # Verificăm ARP spoofing
        if ARP_RULES['enabled'] and protocol == 'ARP':
            self._check_arp_sweep(src_ip, current_time)

        # Verificăm DNS tunneling
        dns_query = packet_info.get('dns_query')
        if DNS_TUNNELING_RULES['enabled'] and dns_query:
            self._check_dns_tunneling(src_ip, dst_ip, dns_query, current_time)

        # Verificăm DHCP spoofing
        if DHCP_RULES['enabled'] and protocol == 'DHCP':
            self._check_dhcp_spoofing(src_ip, dst_port, current_time)

        # Verificăm packet flood
        if PACKET_FLOOD_RULES['enabled']:
            self._check_packet_flood(src_ip, current_time)

        # Verificăm protocoale nesecurizate
        if INSECURE_PROTOCOL_RULES['enabled'] and dst_port:
            self._check_insecure_protocol(src_ip, dst_port, current_time)

        # Verificăm SYN flood (conexiuni TCP brute)
        if SYN_FLOOD_RULES['enabled'] and dst_port and protocol == 'TCP':
            self._check_syn_flood(src_ip, dst_ip, dst_port, current_time)

    def _check_port_scan(self, src_ip, dst_ip, dst_port, current_time):
        """Detectează scanarea porturilor."""
        rules = PORT_SCAN_RULES
        window = rules['window_seconds']
        tracker = self._port_scan_tracker[src_ip]

        # Adaugă portul curent
        tracker.append((current_time, dst_port))

        # Elimină intrările vechi
        cutoff = current_time - window
        while tracker and tracker[0][0] < cutoff:
            tracker.popleft()

        # Numără porturile unice accesate în fereastra de timp
        unique_ports = set(p for _, p in tracker)
        if len(unique_ports) >= rules['threshold']:
            self._fire_alert(
                alert_type='port_scan',
                source_ip=src_ip,
                destination_ip=dst_ip,
                port=dst_port,
                message=f"Port scanning detectat: {src_ip} a scanat {len(unique_ports)} "
                        f"porturi în {window} secunde.",
                severity=rules['severity']
            )
            # Resetăm tracker-ul pentru a evita alerte duplicate
            self._port_scan_tracker[src_ip].clear()

    def _check_brute_force(self, src_ip, dst_ip, dst_port, current_time):
        """Detectează atacuri brute force pe servicii."""
        rules = BRUTE_FORCE_RULES
        window = rules['window_seconds']
        tracker = self._brute_force_tracker[src_ip][dst_port]

        # Adaugă conexiunea curentă
        tracker.append(current_time)

        # Elimină intrările vechi
        cutoff = current_time - window
        while tracker and tracker[0] < cutoff:
            tracker.popleft()

        # Verificăm pragul
        if len(tracker) >= rules['threshold']:
            service_name = rules['monitored_ports'].get(dst_port, f'Port {dst_port}')
            self._fire_alert(
                alert_type='brute_force',
                source_ip=src_ip,
                destination_ip=dst_ip,
                port=dst_port,
                message=f"Atac brute force detectat: {src_ip} a trimis {len(tracker)} "
                        f"conexiuni către {service_name} (port {dst_port}) în {window} secunde.",
                severity=rules['severity']
            )
            # Resetăm tracker-ul
            self._brute_force_tracker[src_ip][dst_port].clear()

    def _check_high_traffic(self, src_ip, size, current_time):
        """Detectează volume mari de trafic de la un singur IP."""
        rules = HIGH_TRAFFIC_RULES
        window = rules['window_seconds']
        tracker = self._traffic_tracker[src_ip]

        # Adaugă pachetul curent
        tracker.append((current_time, size))

        # Elimină intrările vechi
        cutoff = current_time - window
        while tracker and tracker[0][0] < cutoff:
            tracker.popleft()

        # Calculează volumul total în fereastra de timp
        total_bytes = sum(s for _, s in tracker)
        if total_bytes >= rules['threshold_bytes']:
            mb = total_bytes / (1024 * 1024)
            self._fire_alert(
                alert_type='high_traffic',
                source_ip=src_ip,
                message=f"Trafic anormal detectat: {src_ip} a transmis {mb:.2f} MB "
                        f"în {window} secunde.",
                severity=rules['severity']
            )
            # Resetăm tracker-ul
            self._traffic_tracker[src_ip].clear()

    def _check_arp_sweep(self, src_ip, current_time):
        """Detectează ARP sweeping (posibil ARP spoofing sau scanare de rețea)."""
        rules = ARP_RULES
        window = rules['window_seconds']
        tracker = self._arp_tracker[src_ip]

        tracker.append(current_time)

        # Elimină intrările vechi
        cutoff = current_time - window
        while tracker and tracker[0] < cutoff:
            tracker.popleft()

        if len(tracker) >= rules['threshold']:
            self._fire_alert(
                alert_type='arp_sweep',
                source_ip=src_ip,
                message=f"ARP sweep detectat: {src_ip} a trimis {len(tracker)} "
                        f"cereri ARP în {window} secunde.",
                severity=rules['severity']
            )
            self._arp_tracker[src_ip].clear()

    def _check_dns_tunneling(self, src_ip, dst_ip, dns_query, current_time):
        """Detectează DNS tunneling prin analiza query-urilor DNS."""
        rules = DNS_TUNNELING_RULES
        window = rules['window_seconds']
        tracker = self._dns_tracker[src_ip]

        # Verifică dacă query-ul este înspre un server DNS de încredere
        trusted_servers = rules.get('trusted_dns_servers', frozenset())
        is_trusted = dst_ip in trusted_servers
        logger.debug(
            "[DNS] Query: %s → %s for %s (trusted: %s)",
            src_ip, dst_ip, dns_query[:_DNS_QUERY_MAX_DISPLAY_LEN],
            'Y' if is_trusted else 'N',
        )
        if is_trusted:
            return

        tracker.append((current_time, dns_query))

        # Elimină intrările vechi
        cutoff = current_time - window
        while tracker and tracker[0][0] < cutoff:
            tracker.popleft()

        # Verifică subdomain anormal de lung
        parts = dns_query.split('.')
        if len(parts) > 2:
            subdomain = '.'.join(parts[:-2])
            if len(subdomain) > rules['max_subdomain_length']:
                self._fire_alert(
                    alert_type='dns_tunneling',
                    source_ip=src_ip,
                    message=(f"DNS tunneling posibil: {src_ip} a trimis un query cu subdomain "
                             f"anormal de lung ({len(subdomain)} caractere): "
                             f"{dns_query[:_DNS_QUERY_MAX_DISPLAY_LEN]}"),
                    severity=rules['severity'],
                )
                self._dns_tracker[src_ip].clear()
                return

        # Verifică număr mare de query-uri DNS unice în fereastră
        unique_queries = {q for _, q in tracker}
        if len(unique_queries) >= rules['unique_queries_threshold']:
            self._fire_alert(
                alert_type='dns_tunneling',
                source_ip=src_ip,
                message=(f"DNS tunneling posibil: {src_ip} a trimis {len(unique_queries)} "
                         f"query-uri DNS unice în {window} secunde."),
                severity=rules['severity'],
            )
            self._dns_tracker[src_ip].clear()
            return

        # Verifică pattern de encoding (hex / base64) în primul subdomain
        if len(parts) > 2:
            first_label = parts[0]
            if len(first_label) > 8:
                hex_ratio = sum(1 for c in first_label if c in _HEX_CHARS) / len(first_label)
                b64_ratio = sum(1 for c in first_label if c in _B64_CHARS) / len(first_label)
                if hex_ratio > 0.8 or b64_ratio > 0.9:
                    self._fire_alert(
                        alert_type='dns_tunneling',
                        source_ip=src_ip,
                        message=(f"DNS tunneling posibil: {src_ip} folosește subdomenii cu "
                                 f"pattern de encoding în query-ul DNS: "
                                 f"{dns_query[:_DNS_QUERY_MAX_DISPLAY_LEN]}"),
                        severity=rules['severity'],
                    )
                    self._dns_tracker[src_ip].clear()

    def _check_dhcp_spoofing(self, src_ip, dst_port, current_time):
        """Detectează un DHCP rogue server în rețea."""
        rules = DHCP_RULES
        # Verificăm doar pachetele DHCP reply (server→client: dst_port=68)
        if dst_port != 68:
            return

        legitimate_servers = set(rules['legitimate_servers'])
        if src_ip in legitimate_servers or self._is_whitelisted(src_ip):
            return

        # Cooldown: nu genera alertă pentru același IP mai des de o dată la 5 minute
        last_alert = self._dhcp_spoof_cooldown.get(src_ip, 0)
        if current_time - last_alert < 300:
            return

        self._dhcp_spoof_cooldown[src_ip] = current_time
        self._fire_alert(
            alert_type='dhcp_spoofing',
            source_ip=src_ip,
            message=(f"DHCP spoofing posibil: {src_ip} trimite pachete DHCP reply "
                     f"dar nu este un server DHCP legitim."),
            severity=rules['severity'],
        )

    def _check_packet_flood(self, src_ip, current_time):
        """Detectează packet flood de la un singur IP."""
        rules = PACKET_FLOOD_RULES
        window = rules['window_seconds']
        tracker = self._packet_flood_tracker[src_ip]

        tracker.append(current_time)

        # Elimină intrările vechi
        cutoff = current_time - window
        while tracker and tracker[0] < cutoff:
            tracker.popleft()

        if len(tracker) >= rules['threshold']:
            self._fire_alert(
                alert_type='packet_flood',
                source_ip=src_ip,
                message=(f"Packet flood detectat: {src_ip} a trimis {len(tracker)} "
                         f"pachete în {window} secunde."),
                severity=rules['severity'],
            )
            self._packet_flood_tracker[src_ip].clear()

    def _check_insecure_protocol(self, src_ip, dst_port, current_time):
        """Detectează utilizarea protocoalelor nesecurizate."""
        rules = INSECURE_PROTOCOL_RULES
        monitored = rules['monitored_ports']

        if dst_port not in monitored:
            return

        # Cooldown: alertează o dată la 10 minute per IP/port
        key = (src_ip, dst_port)
        last_alert = self._insecure_protocol_cooldown.get(key, 0)
        if current_time - last_alert < rules['cooldown_seconds']:
            return

        protocol_name = monitored[dst_port]
        self._insecure_protocol_cooldown[key] = current_time
        self._fire_alert(
            alert_type='insecure_protocol',
            source_ip=src_ip,
            port=dst_port,
            message=(f"Protocol nesecurizat detectat: {src_ip} folosește "
                     f"{protocol_name} (port {dst_port})."),
            severity=rules['severity'],
        )

    def _check_syn_flood(self, src_ip, dst_ip, dst_port, current_time):
        """Detectează SYN flood (număr mare de conexiuni TCP către același port)."""
        rules = SYN_FLOOD_RULES
        window = rules['window_seconds']
        tracker = self._syn_flood_tracker[src_ip][dst_port]

        tracker.append(current_time)

        # Elimină intrările vechi
        cutoff = current_time - window
        while tracker and tracker[0] < cutoff:
            tracker.popleft()

        if len(tracker) >= rules['threshold']:
            self._fire_alert(
                alert_type='syn_flood',
                source_ip=src_ip,
                destination_ip=dst_ip,
                port=dst_port,
                message=(f"SYN flood detectat: {src_ip} a trimis {len(tracker)} "
                         f"conexiuni TCP către portul {dst_port} în {window} secunde."),
                severity=rules['severity'],
            )
            self._syn_flood_tracker[src_ip][dst_port].clear()


# Instanța globală a detectorului
detector = IntrusionDetector()
