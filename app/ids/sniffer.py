"""
Modulul de captură a pachetelor de rețea.
Folosește Scapy pentru captură reală sau generează trafic simulat pentru testare.
"""
import threading
import time
import random
import socket
import ipaddress
from datetime import datetime, timezone
from collections import defaultdict

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


def _is_private_ip(ip_str):
    """Verifică dacă un IP este privat (RFC1918)."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def _detect_device_type(ip_str):
    """Auto-detectează tipul dispozitivului pe baza intervalelor de IP din rețeaua școlii."""
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
    # Puncte de acces wireless: .161-.169 și .177-.178
    if _ip_int('192.168.2.161') <= ip_int <= _ip_int('192.168.2.169'):
        return 'ap'
    if ip_str in ('192.168.2.177', '192.168.2.178'):
        return 'ap'
    # NVR și Camere supraveghere: .80, .91-.96, .160, .170-.176
    if ip_str in ('192.168.2.80', '192.168.2.160'):
        return 'camera'
    if _ip_int('192.168.2.91') <= ip_int <= _ip_int('192.168.2.96'):
        return 'camera'
    if _ip_int('192.168.2.170') <= ip_int <= _ip_int('192.168.2.176'):
        return 'camera'
    # Servere: .241-.243
    if _ip_int('192.168.2.241') <= ip_int <= _ip_int('192.168.2.243'):
        return 'server'

    return 'client'


def _update_device_buffer(ip, mac, size, vlan_id=None):
    """Actualizează buffer-ul de dispozitive în memorie (non-blocant)."""
    if not ip or not _is_private_ip(ip):
        return
    now = datetime.utcnow()
    with _device_buffer_lock:
        if ip in _device_buffer:
            entry = _device_buffer[ip]
            entry['packets'] += 1
            entry['bytes'] += size
            entry['last_seen'] = now
            if mac and not entry.get('mac'):
                entry['mac'] = mac
            if vlan_id is not None:
                entry['vlan_id'] = vlan_id
        else:
            _device_buffer[ip] = {
                'mac': mac,
                'packets': 1,
                'bytes': size,
                'last_seen': now,
                'is_new': True,
                'vlan_id': vlan_id,
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

            for ip, data in snapshot.items():
                try:
                    device = NetworkDevice.query.filter_by(ip_address=ip).first()
                    if device:
                        device.last_seen = data['last_seen']
                        device.total_packets = (device.total_packets or 0) + data['packets']
                        device.total_bytes = (device.total_bytes or 0) + data['bytes']
                        if data.get('mac') and not device.mac_address:
                            device.mac_address = data['mac']
                        if data.get('vlan_id') is not None:
                            device.vlan = str(data['vlan_id'])
                    else:
                        is_known = ip in WHITELIST_IPS
                        device_type = _detect_device_type(ip)
                        device = NetworkDevice(
                            ip_address=ip,
                            mac_address=data.get('mac'),
                            device_type=device_type,
                            first_seen=data['last_seen'],
                            last_seen=data['last_seen'],
                            total_packets=data['packets'],
                            total_bytes=data['bytes'],
                            is_known=is_known,
                            vlan=str(data['vlan_id']) if data.get('vlan_id') is not None else None,
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
    except Exception as e:
        print(f"[Sniffer] Eroare la flush dispozitive: {e}")

    _last_device_flush = time.monotonic()


def _maybe_flush_devices(app):
    """Apelează flush-ul dacă a trecut intervalul de timp."""
    global _last_device_flush
    if time.monotonic() - _last_device_flush >= _DEVICE_FLUSH_INTERVAL:
        _flush_device_buffer(app)


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
    _update_device_buffer(src_ip, src_mac, size, vlan_id=vlan_id)

    # Flush periodic la baza de date (non-blocant când nu e momentul)
    _maybe_flush_devices(app)

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
        from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS
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
        from scapy.all import Ether, IP, TCP, UDP as ScapyUDP, ICMP, ARP, DNS, Dot1Q
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
        devices = NetworkDevice.query.all()
        for device in devices:
            correct_type = _detect_device_type(device.ip_address)
            if correct_type != device.device_type:
                print(f"[Sniffer] Dispozitiv reclasificat: {device.ip_address} {device.device_type} → {correct_type}")
                device.device_type = correct_type
        db.session.commit()
    except Exception as e:
        print(f"[Sniffer] Eroare la reclasificarea dispozitivelor: {e}")
        db.session.rollback()


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

    # Reclasificăm dispozitivele cu tip greșit la pornire
    with app.app_context():
        _fix_device_types(app)

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
