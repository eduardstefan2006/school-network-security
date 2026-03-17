"""
Server syslog UDP intern pentru primirea log-urilor firewall de la RouterOS.

Ascultă pe portul UDP 514 (configurabil prin SYSLOG_PORT) și parsează
mesajele cu prefix SCHOOLSEC-DROP-* sau SCHOOLSEC-REJECT-* trimise de
RouterOS, stocând rezultatele în tabela FirewallLog din baza de date.

Format log RouterOS:
    SCHOOLSEC-DROP-FWD: in:ether1 out:ether2, src-mac AA:BB:CC:DD:EE:FF,
    proto TCP (SYN), 1.2.3.4:54321->10.0.0.1:80, len 60
"""
import re
import socket
import threading
import time
from datetime import datetime, timezone

# Regex pentru detectarea prefixului firewall generat de SchoolSec
_FW_PREFIX_RE = re.compile(r'SCHOOLSEC-(DROP|REJECT)-\w+', re.IGNORECASE)

# Regex pentru extragerea perechii src_ip:src_port->dst_ip:dst_port
# Fiecare octet este limitat la intervalul 0-255
_OCTET = r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
_IP_PORT_RE = re.compile(
    rf'({_OCTET}(?:\.{_OCTET}){{3}}):(\d+)->({_OCTET}(?:\.{_OCTET}){{3}}):(\d+)'
)

# Regex pentru extragerea protocolului (ex: "proto TCP")
_PROTO_RE = re.compile(r'\bproto\s+(\w+)', re.IGNORECASE)


def _parse_firewall_message(message: str) -> dict | None:
    """Parsează un mesaj syslog firewall de la RouterOS.

    Returnează un dict cu cheile:
        src_ip, dst_ip, src_port, dst_port, protocol, action, raw_message
    sau None dacă mesajul nu conține prefixul SCHOOLSEC-DROP/REJECT.
    """
    prefix_match = _FW_PREFIX_RE.search(message)
    if prefix_match is None:
        return None

    action = 'reject' if 'REJECT' in prefix_match.group(0).upper() else 'drop'

    src_ip = dst_ip = None
    src_port = dst_port = None

    ip_match = _IP_PORT_RE.search(message)
    if ip_match:
        src_ip = ip_match.group(1)
        src_port = int(ip_match.group(2))
        dst_ip = ip_match.group(3)
        dst_port = int(ip_match.group(4))

    proto_match = _PROTO_RE.search(message)
    protocol = proto_match.group(1).upper() if proto_match else None

    return {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'action': action,
        'raw_message': message,
    }


def _strip_syslog_priority(message: str) -> str:
    """Elimină prefixul de prioritate syslog RFC 3164 (<N>) din mesaj."""
    if message.startswith('<'):
        gt = message.find('>')
        if gt != -1:
            return message[gt + 1:].strip()
    return message


def start_syslog_server(app):
    """Pornește serverul syslog UDP într-un thread daemon de background.

    Citește SYSLOG_LISTEN_ADDRESS și SYSLOG_PORT din configurația aplicației.
    Dacă bind-ul eșuează (de exemplu portul 514 necesită privilegii root),
    afișează un mesaj de avertizare și returnează fără a bloca pornirea app.
    """
    listen_address = app.config.get('SYSLOG_LISTEN_ADDRESS', '0.0.0.0')
    port = app.config.get('SYSLOG_PORT', 514)

    def _run():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((listen_address, port))
            sock.settimeout(1.0)
            print(f"[Syslog] Server pornit pe {listen_address}:{port} (UDP)")
        except PermissionError:
            print(
                f"[Syslog] Permisiune refuzată la bind pe portul {port}. "
                f"Rulați cu privilegii root sau setați SYSLOG_PORT la un port > 1024."
            )
            return
        except OSError as e:
            print(f"[Syslog] Nu s-a putut porni serverul syslog: {e}")
            return

        while True:
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[Syslog] Eroare recvfrom: {e}")
                time.sleep(1)
                continue

            try:
                raw = data.decode('utf-8', errors='replace').strip()
                message = _strip_syslog_priority(raw)
                parsed = _parse_firewall_message(message)
                if parsed is None:
                    continue

                with app.app_context():
                    from app import db
                    from app.models import FirewallLog

                    entry = FirewallLog(
                        timestamp=datetime.now(timezone.utc),
                        **parsed,
                    )
                    db.session.add(entry)
                    try:
                        db.session.commit()
                    except Exception as db_err:
                        db.session.rollback()
                        print(f"[Syslog] Eroare la salvarea în BD: {db_err}")
            except Exception as e:
                print(f"[Syslog] Eroare la procesarea mesajului syslog: {e}")

    thread = threading.Thread(target=_run, daemon=True, name='syslog-server')
    thread.start()
