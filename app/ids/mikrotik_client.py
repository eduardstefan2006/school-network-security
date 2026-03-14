"""
Client MikroTik RouterOS API pentru integrarea cu routerul școlii.
Folosește librouteros pentru conexiunea la API-ul nativ RouterOS.
"""
import time


def _split_address_port(addr: str):
    """Extrage adresa IP și portul dintr-un string RouterOS de tipul ip:port sau [ipv6]:port.

    Suportă IPv4 (192.168.1.1:80), IPv6 ([2001:db8::1]:80) și adrese fără port.
    Returnează tuplu (ip, port).
    """
    if not addr:
        return ('', '')
    # IPv6 cu paranteze pătrate: [2001:db8::1]:80
    if addr.startswith('['):
        bracket_end = addr.find(']')
        if bracket_end != -1:
            ip = addr[1:bracket_end]
            port = addr[bracket_end + 2:] if addr[bracket_end + 1:bracket_end + 2] == ':' else ''
            return (ip, port)
    # IPv4 cu port: 192.168.1.1:80
    if addr.count(':') == 1:
        ip, _, port = addr.rpartition(':')
        return (ip, port)
    # IPv6 fără port sau alte formate
    return (addr, '')


class MikrotikClient:
    """Client pentru RouterOS API folosind librouteros."""

    def __init__(self, host: str, port: int = 8728, username: str = 'admin', password: str = ''):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self._connection = None

    # ------------------------------------------------------------------
    # Conexiune
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Conectare la RouterOS API cu retry logic (3 încercări, 5s între ele)."""
        for attempt in range(1, 4):
            try:
                import librouteros
                self._connection = librouteros.connect(
                    self.host,
                    username=self.username,
                    password=self.password,
                    port=self.port,
                )
                print(f"[MikroTik] Conectat la {self.host}:{self.port}")
                return True
            except Exception as e:
                print(f"[MikroTik] Eroare conectare (încercarea {attempt}/3): {e}")
                if attempt < 3:
                    time.sleep(5)
        self._connection = None
        return False

    def disconnect(self):
        """Închide conexiunea cu routerul."""
        try:
            if self._connection is not None:
                self._connection.close()
                print("[MikroTik] Deconectat.")
        except Exception as e:
            print(f"[MikroTik] Eroare la deconectare: {e}")
        finally:
            self._connection = None

    def is_connected(self) -> bool:
        """Returnează True dacă conexiunea este activă."""
        return self._connection is not None

    # ------------------------------------------------------------------
    # Date RouterOS
    # ------------------------------------------------------------------

    def get_dhcp_leases(self) -> list:
        """Returnează lista sesiunilor DHCP active de pe router.

        Endpoint RouterOS: /ip/dhcp-server/lease
        Câmpuri returnate: ip, mac, hostname, status, expires_after, comment
        """
        if not self.is_connected():
            return []
        try:
            leases = []
            for item in self._connection('/ip/dhcp-server/lease/print'):
                leases.append({
                    'ip': item.get('address', ''),
                    'mac': item.get('mac-address', ''),
                    'hostname': item.get('host-name', ''),
                    'status': item.get('status', ''),
                    'expires_after': item.get('expires-after', ''),
                    'comment': item.get('comment', ''),
                })
            return leases
        except Exception as e:
            print(f"[MikroTik] Eroare get_dhcp_leases: {e}")
            return []

    def get_active_connections(self) -> list:
        """Returnează conexiunile active din firewall.

        Endpoint RouterOS: /ip/firewall/connection
        Câmpuri returnate: src_ip, dst_ip, protocol, src_port, dst_port, bytes, packets, tcp_state
        """
        if not self.is_connected():
            return []
        try:
            connections = []
            for item in self._connection('/ip/firewall/connection/print'):
                src = item.get('src-address', '')
                dst = item.get('dst-address', '')
                src_ip, src_port = _split_address_port(src)
                dst_ip, dst_port = _split_address_port(dst)
                connections.append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': item.get('protocol', ''),
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'bytes': item.get('orig-bytes', '0'),
                    'packets': item.get('orig-packets', '0'),
                    'tcp_state': item.get('tcp-state', ''),
                })
            return connections
        except Exception as e:
            print(f"[MikroTik] Eroare get_active_connections: {e}")
            return []

    def get_interface_traffic(self) -> list:
        """Returnează statistici trafic per interfață.

        Endpoint RouterOS: /interface
        Câmpuri returnate: name, rx_bytes, tx_bytes, rx_packets, tx_packets, running
        """
        if not self.is_connected():
            return []
        try:
            interfaces = []
            for item in self._connection('/interface/print'):
                interfaces.append({
                    'name': item.get('name', ''),
                    'rx_bytes': item.get('rx-byte', '0'),
                    'tx_bytes': item.get('tx-byte', '0'),
                    'rx_packets': item.get('rx-packet', '0'),
                    'tx_packets': item.get('tx-packet', '0'),
                    'running': item.get('running', False),
                })
            return interfaces
        except Exception as e:
            print(f"[MikroTik] Eroare get_interface_traffic: {e}")
            return []

    def get_arp_table(self) -> list:
        """Returnează tabela ARP a routerului.

        Endpoint RouterOS: /ip/arp
        Câmpuri returnate: ip, mac, interface, complete
        """
        if not self.is_connected():
            return []
        try:
            arp = []
            for item in self._connection('/ip/arp/print'):
                arp.append({
                    'ip': item.get('address', ''),
                    'mac': item.get('mac-address', ''),
                    'interface': item.get('interface', ''),
                    'complete': item.get('complete', False),
                })
            return arp
        except Exception as e:
            print(f"[MikroTik] Eroare get_arp_table: {e}")
            return []

    def block_ip_on_router(self, ip_address: str, comment: str = '') -> bool:
        """Adaugă IP-ul în address-list schoolsec-blocked pe router.

        Endpoint RouterOS: /ip/firewall/address-list
        Returnează True dacă reușit, False dacă eroare.
        """
        if not self.is_connected():
            return False
        try:
            self._connection('/ip/firewall/address-list/add', **{
                'list': 'schoolsec-blocked',
                'address': ip_address,
                'comment': comment,
            })
            print(f"[MikroTik] IP {ip_address} adăugat în schoolsec-blocked.")
            return True
        except Exception as e:
            print(f"[MikroTik] Eroare block_ip_on_router({ip_address}): {e}")
            return False

    def unblock_ip_on_router(self, ip_address: str) -> bool:
        """Elimină IP-ul din address-list schoolsec-blocked.

        Returnează True dacă reușit, False dacă eroare.
        """
        if not self.is_connected():
            return False
        try:
            entries = list(self._connection('/ip/firewall/address-list/print', **{
                '?list': 'schoolsec-blocked',
                '?address': ip_address,
            }))
            if not entries:
                print(f"[MikroTik] IP {ip_address} nu a fost găsit în schoolsec-blocked.")
                return False
            for entry in entries:
                self._connection('/ip/firewall/address-list/remove', **{
                    '.id': entry['.id'],
                })
            print(f"[MikroTik] IP {ip_address} eliminat din schoolsec-blocked.")
            return True
        except Exception as e:
            print(f"[MikroTik] Eroare unblock_ip_on_router({ip_address}): {e}")
            return False

    def get_router_identity(self) -> str:
        """Returnează numele routerului MikroTik.

        Endpoint RouterOS: /system/identity
        """
        if not self.is_connected():
            return ''
        try:
            result = list(self._connection('/system/identity/print'))
            if result:
                return result[0].get('name', '')
        except Exception as e:
            print(f"[MikroTik] Eroare get_router_identity: {e}")
        return ''

    # ------------------------------------------------------------------
    # Securitate externă
    # ------------------------------------------------------------------

    def get_firewall_log(self, limit=200) -> list:
        """Citește ultimele intrări din logul RouterOS filtrate pe topic 'firewall'.

        Endpoint RouterOS: /log/print
        Filtrare: topics conține 'firewall'
        Returnează: lista de dict-uri cu time, topics, message
        """
        if not self.is_connected():
            return []
        try:
            entries = []
            for item in self._connection('/log/print'):
                topics = item.get('topics', '')
                if 'firewall' in topics:
                    entries.append({
                        'time': item.get('time', ''),
                        'topics': topics,
                        'message': item.get('message', ''),
                    })
                    if len(entries) >= limit:
                        break
            return entries
        except Exception as e:
            print(f"[MikroTik] Eroare get_firewall_log: {e}")
            return []

    def get_system_resources(self) -> dict:
        """Returnează starea resurselor routerului (CPU, RAM, uptime).

        Endpoint RouterOS: /system/resource/print
        Returnează: dict cu cpu_load, free_memory, total_memory, uptime, version, board_name
        """
        if not self.is_connected():
            return {}
        try:
            result = list(self._connection('/system/resource/print'))
            if result:
                item = result[0]
                free_mem = int(item.get('free-memory', 0))
                total_mem = int(item.get('total-memory', 1))
                return {
                    'cpu_load': int(item.get('cpu-load', 0)),
                    'free_memory': free_mem,
                    'total_memory': total_mem,
                    'uptime': item.get('uptime', ''),
                    'version': item.get('version', ''),
                    'board_name': item.get('board-name', ''),
                }
        except Exception as e:
            print(f"[MikroTik] Eroare get_system_resources: {e}")
        return {}

    def get_login_attempts(self, limit=100) -> list:
        """Citește logurile de login din RouterOS (reușite și eșuate).

        Endpoint RouterOS: /log/print
        Filtrare: topics conține 'system' și message conține 'login' sau 'logged in' sau 'login failure'
        Returnează: lista de dict-uri cu time, message, ip (extras din mesaj)
        """
        if not self.is_connected():
            return []
        try:
            import re
            entries = []
            _ip_re = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
            for item in self._connection('/log/print'):
                topics = item.get('topics', '')
                message = item.get('message', '').lower()
                if 'system' in topics and ('login' in message or 'logged in' in message):
                    raw_msg = item.get('message', '')
                    ip_match = _ip_re.search(raw_msg)
                    entries.append({
                        'time': item.get('time', ''),
                        'topics': topics,
                        'message': raw_msg,
                        'ip': ip_match.group(1) if ip_match else '',
                        'success': 'failure' not in message and 'failed' not in message,
                    })
                    if len(entries) >= limit:
                        break
            return entries
        except Exception as e:
            print(f"[MikroTik] Eroare get_login_attempts: {e}")
            return []

    def get_firewall_rules_count(self) -> dict:
        """Returnează numărul de reguli din fiecare chain firewall.

        Endpoint RouterOS: /ip/firewall/filter/print, /ip/firewall/nat/print, /ip/firewall/mangle/print
        Returnează: dict cu filter_rules, nat_rules, mangle_rules
        """
        if not self.is_connected():
            return {}
        result = {}
        for key, endpoint in [
            ('filter_rules', '/ip/firewall/filter/print'),
            ('nat_rules', '/ip/firewall/nat/print'),
            ('mangle_rules', '/ip/firewall/mangle/print'),
        ]:
            try:
                result[key] = len(list(self._connection(endpoint)))
            except Exception as e:
                print(f"[MikroTik] Eroare get_firewall_rules_count ({key}): {e}")
                result[key] = 0
        return result

    def get_address_list_entries(self, list_name='schoolsec-blocked') -> list:
        """Returnează intrările din address list-ul specificat.

        Endpoint RouterOS: /ip/firewall/address-list/print
        Returnează: lista de dict-uri cu address, list, comment, creation_time, timeout
        """
        if not self.is_connected():
            return []
        try:
            entries = []
            for item in self._connection('/ip/firewall/address-list/print', **{
                '?list': list_name,
            }):
                entries.append({
                    'address': item.get('address', ''),
                    'list': item.get('list', ''),
                    'comment': item.get('comment', ''),
                    'creation_time': item.get('creation-time', ''),
                    'timeout': item.get('timeout', ''),
                    '.id': item.get('.id', ''),
                })
            return entries
        except Exception as e:
            print(f"[MikroTik] Eroare get_address_list_entries({list_name}): {e}")
            return []
