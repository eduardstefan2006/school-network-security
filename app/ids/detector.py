"""
Modulul de detectare a intruziunilor (IDS - Intrusion Detection System).
Analizează traficul capturat și detectează comportamente suspecte.
"""
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from app.ids.rules import (
    PORT_SCAN_RULES, BRUTE_FORCE_RULES,
    HIGH_TRAFFIC_RULES, ARP_RULES, WHITELIST_IPS
)

# Cache pentru lista albă personalizată (evită citirea JSON la fiecare pachet)
_whitelist_cache = None
_whitelist_cache_time = 0.0
_WHITELIST_CACHE_TTL = 60  # secunde


def invalidate_whitelist_cache():
    """Invalidează cache-ul listei albe (apelat după fiecare modificare a JSON-ului)."""
    global _whitelist_cache
    _whitelist_cache = None


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

    def _clean_old_entries(self, dq, window_seconds):
        """Elimină intrările mai vechi decât fereastra de timp."""
        cutoff = time.time() - window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def analyze_packet(self, packet_info):
        """
        Analizează informațiile unui pachet și detectează amenințări.
        packet_info este un dicționar cu: src_ip, dst_ip, protocol, src_port, dst_port, size
        """
        src_ip = packet_info.get('src_ip', '')
        dst_ip = packet_info.get('dst_ip', '')
        protocol = packet_info.get('protocol', '')
        dst_port = packet_info.get('dst_port')
        size = packet_info.get('size', 0)

        # Nu analizăm IP-urile din lista albă
        if self._is_whitelisted(src_ip):
            return

        current_time = time.time()

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


# Instanța globală a detectorului
detector = IntrusionDetector()
