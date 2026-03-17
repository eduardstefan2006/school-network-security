"""
Monitorizare securitate externă — analizează logurile MikroTik pentru detectarea
atacurilor din internet asupra routerului și rețelei școlii.
"""
import logging
import re
import ipaddress
from collections import defaultdict, deque
from datetime import datetime, timezone

from app.ids.rules import (
    EXTERNAL_PORT_SCAN_RULES,
    EXTERNAL_BRUTE_FORCE_RULES,
    EXTERNAL_DDOS_RULES,
    ROUTER_HEALTH_RULES,
    EXTERNAL_TRUSTED_IPS,
    EXTERNAL_TRUSTED_SUBNETS,
)

logger = logging.getLogger(__name__)

# Interval cooldown implicit în secunde (5 minute)
_ALERT_COOLDOWN_SECONDS = 300

# Set pentru lookup rapid al IP-urilor de încredere (O(1))
_TRUSTED_IPS_SET: frozenset = frozenset(EXTERNAL_TRUSTED_IPS)
# Rețele VPN de încredere pre-compilate
_TRUSTED_NETWORKS: list = [
    ipaddress.ip_network(s, strict=False) for s in EXTERNAL_TRUSTED_SUBNETS
]

# Regex pentru extragerea portului dintr-un mesaj de log RouterOS
# Exemple: "in:ether1 out:(unknown 0), src-mac ... proto TCP (SYN), 1.2.3.4:54321->10.0.0.1:80"
_PORT_RE = re.compile(r':(\d+)(?:\s*->|$)', re.IGNORECASE)
_IP_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')


def _is_private_ip(ip: str) -> bool:
    """Returnează True dacă IP-ul este privat/loopback."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _is_trusted_ip(ip: str) -> bool:
    """Returnează True dacă IP-ul este de încredere și nu trebuie să genereze alerte externe.

    Un IP este considerat de încredere dacă:
    - este privat (RFC1918 / loopback) — atacurile externe vin întotdeauna de pe IP-uri publice
    - este listat explicit în EXTERNAL_TRUSTED_IPS (tunnel-uri inter-școli, IP-uri publice partenere)
    - aparține unui subnet VPN din EXTERNAL_TRUSTED_SUBNETS (WireGuard, L2TP/PPTP)
    """
    if _is_private_ip(ip):
        return True
    if ip in _TRUSTED_IPS_SET:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _TRUSTED_NETWORKS)
    except ValueError:
        return False


class ExternalMonitor:
    """Monitorizează securitatea externă a routerului MikroTik.

    Analizează logurile firewall și de login pentru a detecta atacuri
    din internet (port scan, brute force, DDoS) și probleme de sănătate
    ale routerului (CPU, RAM).
    """

    def __init__(self, app, mikrotik_client):
        self.app = app
        self.mikrotik_client = mikrotik_client
        # ip -> deque de (timestamp, port_str)
        self._firewall_drop_tracker: dict = defaultdict(deque)
        # ip -> deque de timestamp
        self._login_failure_tracker: dict = defaultdict(deque)
        # deque de timestamp pentru toate drop-urile (DDoS)
        self._ddos_tracker: deque = deque()
        # (alert_type, ip) -> last_alert_time (datetime UTC)
        self._alert_cooldown: dict = {}
        # Cheile logurilor deja procesate: set pentru lookup O(1), deque pentru evicție FIFO
        self._seen_log_keys_set: set = set()
        self._seen_log_keys_queue: deque = deque(maxlen=500)
        print(
            f"[ExternalMonitor] IP-uri de încredere configurate: "
            f"{len(_TRUSTED_IPS_SET)} IP-uri + {len(_TRUSTED_NETWORKS)} subnet-uri VPN."
        )

    # ------------------------------------------------------------------
    # Punct de intrare principal
    # ------------------------------------------------------------------

    def run_check(self):
        """Execută o rundă completă de verificare (apelat periodic din sync thread)."""
        if not self.mikrotik_client.is_connected():
            return
        try:
            self._check_firewall_logs()
        except Exception as exc:
            print(f"[ExternalMonitor] Eroare _check_firewall_logs: {exc}")
        try:
            self._check_login_attempts()
        except Exception as exc:
            print(f"[ExternalMonitor] Eroare _check_login_attempts: {exc}")
        try:
            self._check_router_health()
        except Exception as exc:
            print(f"[ExternalMonitor] Eroare _check_router_health: {exc}")

    # ------------------------------------------------------------------
    # Analiză log firewall
    # ------------------------------------------------------------------

    def _check_firewall_logs(self):
        """Analizează logurile firewall pentru atacuri externe."""
        rules_scan = EXTERNAL_PORT_SCAN_RULES
        rules_ddos = EXTERNAL_DDOS_RULES

        if not rules_scan.get('enabled') and not rules_ddos.get('enabled'):
            return

        logs = self.mikrotik_client.get_firewall_log(limit=200)
        now = datetime.now(timezone.utc)
        new_entries = []

        for entry in logs:
            log_time_str = entry.get('time', '')
            message = entry.get('message', '')
            # Evităm procesarea intrărilor deja văzute
            key = f"{log_time_str}:{message[:60]}"
            if key in self._seen_log_keys_set:
                continue
            new_entries.append(entry)

        # Înregistrăm cheile noi cu evicție FIFO pentru memorie limitată
        for entry in new_entries:
            log_time_str = entry.get('time', '')
            message = entry.get('message', '')
            key = f"{log_time_str}:{message[:60]}"
            if len(self._seen_log_keys_queue) >= self._seen_log_keys_queue.maxlen:
                # Eliminăm cel mai vechi element și din set
                oldest = self._seen_log_keys_queue[0]
                self._seen_log_keys_set.discard(oldest)
            self._seen_log_keys_queue.append(key)
            self._seen_log_keys_set.add(key)

        # Procesăm intrările noi
        for entry in new_entries:
            message = entry.get('message', '')
            message_lower = message.lower()

            # Procesăm doar drop-urile / rejectele
            if 'drop' not in message_lower and 'reject' not in message_lower:
                continue

            # Extragem IP-ul sursă (primul IP din mesaj)
            ips = _IP_RE.findall(message)
            if not ips:
                continue
            src_ip = ips[0]

            # Ignorăm IP-urile de încredere (private, tunnel-uri inter-școli, VPN)
            if _is_trusted_ip(src_ip):
                continue

            # Extragem portul destinație (dacă există)
            port_match = _PORT_RE.search(message)
            port_str = port_match.group(1) if port_match else ''

            self._ddos_tracker.append(now)
            self._firewall_drop_tracker[src_ip].append((now, port_str))

        # Curățare ferestre de timp
        scan_window = rules_scan.get('window_seconds', 60)
        ddos_window = rules_ddos.get('window_seconds', 60)

        # DDoS: verifică totalul de drop-uri
        if rules_ddos.get('enabled'):
            cutoff = now.timestamp() - ddos_window
            while self._ddos_tracker and self._ddos_tracker[0].timestamp() < cutoff:
                self._ddos_tracker.popleft()
            if len(self._ddos_tracker) >= rules_ddos.get('threshold', 1000):
                self._fire_external_alert(
                    alert_type='external_ddos_suspected',
                    source_ip='0.0.0.0',
                    message=(
                        f"DDoS suspectat: {len(self._ddos_tracker)} pachete droppate "
                        f"în ultimele {ddos_window}s."
                    ),
                    severity=rules_ddos.get('severity', 'critical'),
                )

        # Port scan: verifică per IP
        if rules_scan.get('enabled'):
            threshold = rules_scan.get('threshold', 20)
            for src_ip, events in list(self._firewall_drop_tracker.items()):
                cutoff = now.timestamp() - scan_window
                while events and events[0][0].timestamp() < cutoff:
                    events.popleft()
                if not events:
                    continue
                # Număr porturi unice
                unique_ports = {ev[1] for ev in events if ev[1]}
                if len(unique_ports) >= threshold:
                    self._fire_external_alert(
                        alert_type='external_port_scan',
                        source_ip=src_ip,
                        message=(
                            f"Port scan extern detectat de la {src_ip}: "
                            f"{len(unique_ports)} porturi diferite droppate în {scan_window}s."
                        ),
                        severity=rules_scan.get('severity', 'high'),
                        auto_block=True,
                    )

    # ------------------------------------------------------------------
    # Analiză tentative de login
    # ------------------------------------------------------------------

    def _check_login_attempts(self):
        """Verifică tentativele de login pe router."""
        rules_bf = EXTERNAL_BRUTE_FORCE_RULES
        if not rules_bf.get('enabled'):
            return

        attempts = self.mikrotik_client.get_login_attempts(limit=100)
        now = datetime.now(timezone.utc)

        for attempt in attempts:
            src_ip = attempt.get('ip', '').strip()
            success = attempt.get('success', True)
            message = attempt.get('message', '')

            # Login reușit de la IP extern (nu de la IP de încredere)
            if success and src_ip and not _is_trusted_ip(src_ip):
                self._fire_external_alert(
                    alert_type='external_login_success',
                    source_ip=src_ip,
                    message=f"Login reușit pe router de la IP extern {src_ip}: {message}",
                    severity='critical',
                )
                continue

            # Login eșuat de la IP extern (nu de la IP de încredere)
            if not success and src_ip and not _is_trusted_ip(src_ip):
                self._login_failure_tracker[src_ip].append(now)

        # Verifică brute force
        bf_window = rules_bf.get('window_seconds', 300)
        bf_threshold = rules_bf.get('threshold', 5)
        for src_ip, timestamps in list(self._login_failure_tracker.items()):
            cutoff = now.timestamp() - bf_window
            while timestamps and timestamps[0].timestamp() < cutoff:
                timestamps.popleft()
            if len(timestamps) >= bf_threshold:
                self._fire_external_alert(
                    alert_type='external_brute_force',
                    source_ip=src_ip,
                    message=(
                        f"Brute force extern pe router de la {src_ip}: "
                        f"{len(timestamps)} tentative eșuate în {bf_window}s."
                    ),
                    severity=rules_bf.get('severity', 'critical'),
                    auto_block=True,
                )

    # ------------------------------------------------------------------
    # Sănătate router
    # ------------------------------------------------------------------

    def _check_router_health(self):
        """Monitorizează starea routerului (CPU, RAM)."""
        rules = ROUTER_HEALTH_RULES
        if not rules.get('enabled'):
            return

        resources = self.mikrotik_client.get_system_resources()
        if not resources:
            return

        cpu_load = resources.get('cpu_load', 0)
        free_mem = resources.get('free_memory', 0)
        total_mem = resources.get('total_memory', 1)
        free_pct = (free_mem / total_mem * 100) if total_mem else 100

        if cpu_load > rules.get('cpu_threshold', 80):
            self._fire_external_alert(
                alert_type='router_high_cpu',
                source_ip=self.mikrotik_client.host,
                message=f"Router CPU ridicat: {cpu_load}% (prag: {rules['cpu_threshold']}%).",
                severity=rules.get('severity_cpu', 'high'),
            )

        if free_pct < rules.get('memory_threshold', 20):
            self._fire_external_alert(
                alert_type='router_low_memory',
                source_ip=self.mikrotik_client.host,
                message=(
                    f"Router RAM scăzută: {free_pct:.1f}% liberă "
                    f"({free_mem // 1024 // 1024} MB liberi din {total_mem // 1024 // 1024} MB)."
                ),
                severity=rules.get('severity_memory', 'medium'),
            )

    # ------------------------------------------------------------------
    # Creare alertă cu cooldown
    # ------------------------------------------------------------------

    def _fire_external_alert(self, alert_type: str, source_ip: str,
                             message: str, severity: str,
                             auto_block: bool = False):
        """Creează alertă + log + notificare Telegram cu cooldown.

        Cooldown: nu genera aceeași alertă pentru același IP mai des de 5 minute.
        """
        now = datetime.now(timezone.utc)
        cooldown_key = (alert_type, source_ip)
        last_time = self._alert_cooldown.get(cooldown_key)
        if last_time is not None:
            elapsed = (now - last_time).total_seconds()
            if elapsed < _ALERT_COOLDOWN_SECONDS:
                return

        self._alert_cooldown[cooldown_key] = now

        with self.app.app_context():
            try:
                from app import db
                from app.models import Alert, SecurityLog

                alert = Alert(
                    alert_type=alert_type,
                    source_ip=source_ip,
                    destination_ip=None,
                    port=None,
                    message=message,
                    severity=severity,
                    status='active',
                )
                db.session.add(alert)

                log = SecurityLog(
                    event_type='alert_generated',
                    source_ip=source_ip,
                    destination_ip=None,
                    port=None,
                    message=message,
                    severity=severity,
                )
                db.session.add(log)
                db.session.commit()
                logger.info(
                    '[ExternalMonitor] Alertă creată: %s de la %s (severitate: %s)',
                    alert_type,
                    source_ip,
                    severity,
                )

                # Auto-blocare pe MikroTik (pentru atacuri externe)
                if auto_block and source_ip and source_ip != '0.0.0.0':
                    try:
                        self.mikrotik_client.block_ip_on_router(
                            source_ip,
                            comment=f'Auto-blocat SchoolSec ({alert_type})',
                        )
                    except Exception as block_exc:
                        logger.warning('[ExternalMonitor] Eroare auto-block %s: %s', source_ip, block_exc)

                # Notificare Telegram
                from app.notifications.telegram import send_alert_notification
                alert_data = {
                    'alert_type': alert_type,
                    'source_ip': source_ip,
                    'destination_ip': None,
                    'port': None,
                    'message': message,
                    'severity': severity,
                    'timestamp': now,
                }
                send_alert_notification(alert_data, self.app.config)

            except Exception as exc:
                logger.error('[ExternalMonitor] Eroare la salvarea alertei %s: %s', alert_type, exc)
                try:
                    from app import db
                    db.session.rollback()
                except Exception:
                    pass
