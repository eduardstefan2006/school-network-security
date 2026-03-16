"""
Motor de auto-descoperire a topologiei de rețea.

Interogează RouterOS API pentru a detecta automat:
- Interfețe și VLAN-uri active
- Dispozitive conectate (ARP + DHCP leases)
- Clasificarea tipurilor de dispozitive
- Topologia rețelei

Populează baza de date fără nicio configurare manuală.
"""
import ipaddress
import threading
from datetime import datetime, timezone


# Starea curentă a procesului de descoperire (accesibilă din rute)
_discovery_state = {
    'running': False,
    'progress': 0,           # 0-100
    'step': '',              # mesaj curent
    'vlans_found': 0,
    'devices_found': 0,
    'completed': False,
    'error': None,
    'started_at': None,
    'finished_at': None,
}
_state_lock = threading.Lock()


def get_discovery_state() -> dict:
    """Returnează o copie a stării curente a procesului de descoperire."""
    with _state_lock:
        return dict(_discovery_state)


def _update_state(**kwargs):
    with _state_lock:
        _discovery_state.update(kwargs)


# ---------------------------------------------------------------------------
# Funcții ajutătoare de clasificare
# ---------------------------------------------------------------------------

def _classify_device_type(ip: str, mac: str | None, hostname: str | None,
                           comment: str | None) -> str:
    """Clasifică tipul unui dispozitiv pe baza IP/MAC/hostname/comment.

    Prioritate:
    1. Comment DHCP conține cuvinte cheie (camera, switch, server, router, ap)
    2. Hostname conține cuvinte cheie
    3. Fallback → 'client'
    """
    # Hint din comment DHCP
    hint_str = ' '.join(filter(None, [comment, hostname])).lower()
    if any(k in hint_str for k in ('camera', 'cam', 'nvr', 'dvr')):
        return 'camera'
    if any(k in hint_str for k in ('switch', 'sw-', 'sw_')):
        return 'switch'
    if any(k in hint_str for k in ('server', 'srv', 'pihole', 'librenms', 'schoolsec')):
        return 'server'
    if any(k in hint_str for k in ('router', 'mikrotik', 'cisco', 'rb3011', 'rb4011')):
        return 'router'
    if any(k in hint_str for k in (' ap', 'ap-', 'ap_', 'access-point', 'tplink', 'asus')):
        return 'ap'

    # Fallback la OUI/hostname detection din sniffer dacă MAC disponibil
    if mac:
        try:
            from app.ids.sniffer import _looks_like_camera, _looks_like_mobile, _looks_like_ap
            if _looks_like_camera(mac):
                return 'camera'
            if _looks_like_mobile(mac):
                return 'mobile'
        except Exception:
            pass

    if hostname:
        try:
            from app.ids.sniffer import _hostname_suggests_mobile
            if _hostname_suggests_mobile(hostname):
                return 'mobile'
        except Exception:
            pass

    return 'client'


# ---------------------------------------------------------------------------
# Funcții principale de descoperire
# ---------------------------------------------------------------------------

def _discover_vlans(mikrotik_client) -> list[dict]:
    """Interogează RouterOS pentru a obține VLAN-urile și subnet-urile lor.

    Îmbină datele din /interface/vlan și /ip/address pentru a construi
    o listă de VLANuri cu subnet-urile lor.

    Returns:
        List of dicts: [{vlan_id, subnet, name, interface}, ...]
    """
    vlans = []
    try:
        conn = mikrotik_client._connection
        if conn is None:
            return vlans

        # Obținem interfețele VLAN
        vlan_ifaces = {}
        try:
            for item in conn('/interface/vlan/print'):
                vid = item.get('vlan-id', '')
                name = item.get('name', '')
                iface = item.get('interface', '')
                if vid:
                    try:
                        vlan_ifaces[name] = {
                            'vlan_id': int(vid),
                            'name': name,
                            'interface': iface,
                        }
                    except (ValueError, TypeError):
                        pass
        except Exception as e:
            print(f"[AutoDiscovery] Eroare la citirea VLAN-urilor: {e}")

        # Obținem adresele IP pentru a asocia subnet-urile cu interfețele
        try:
            for item in conn('/ip/address/print'):
                iface_name = item.get('interface', '')
                address = item.get('address', '')  # ex: '192.168.221.1/28'
                if iface_name in vlan_ifaces and address:
                    try:
                        net = ipaddress.ip_interface(address).network
                        vlan_ifaces[iface_name]['subnet'] = str(net)
                    except ValueError:
                        pass
        except Exception as e:
            print(f"[AutoDiscovery] Eroare la citirea adreselor IP: {e}")

        vlans = list(vlan_ifaces.values())
        print(f"[AutoDiscovery] {len(vlans)} VLAN-uri găsite.")
    except Exception as e:
        print(f"[AutoDiscovery] Eroare la descoperirea VLAN-urilor: {e}")

    return vlans


def _discover_devices(mikrotik_client) -> list[dict]:
    """Scanează dispozitivele conectate via DHCP leases + tabel ARP.

    Returns:
        List of dicts: [{ip, mac, hostname, comment, device_type}, ...]
    """
    devices = {}

    # DHCP leases (sursă principală)
    try:
        leases = mikrotik_client.get_dhcp_leases()
        for lease in leases:
            ip = lease.get('ip', '').strip()
            if not ip:
                continue
            devices[ip] = {
                'ip': ip,
                'mac': lease.get('mac', '').strip() or None,
                'hostname': lease.get('hostname', '').strip() or None,
                'comment': lease.get('comment', '').strip() or None,
                'source': 'dhcp',
            }
        print(f"[AutoDiscovery] {len(leases)} DHCP leases citite.")
    except Exception as e:
        print(f"[AutoDiscovery] Eroare la citirea DHCP leases: {e}")

    # Tabel ARP (completează MAC-uri lipsă și adaugă dispozitive fără DHCP)
    try:
        arp_entries = mikrotik_client.get_arp_table()
        for entry in arp_entries:
            ip = entry.get('ip', '').strip()
            mac = entry.get('mac', '').strip()
            if not ip:
                continue
            if ip not in devices:
                devices[ip] = {
                    'ip': ip,
                    'mac': mac or None,
                    'hostname': None,
                    'comment': None,
                    'source': 'arp',
                }
            elif not devices[ip].get('mac') and mac:
                devices[ip]['mac'] = mac
        print(f"[AutoDiscovery] {len(arp_entries)} intrări ARP citite.")
    except Exception as e:
        print(f"[AutoDiscovery] Eroare la citirea tabelului ARP: {e}")

    # Clasificare device type
    result = []
    for ip, dev in devices.items():
        dev['device_type'] = _classify_device_type(
            ip, dev.get('mac'), dev.get('hostname'), dev.get('comment')
        )
        result.append(dev)

    print(f"[AutoDiscovery] Total dispozitive descoperite: {len(result)}.")
    return result


def _save_vlans_to_db(vlans: list[dict], app) -> int:
    """Salvează VLAN-urile descoperite în baza de date.

    Actualizează înregistrările existente sau creează altele noi.
    Returnează numărul de VLAN-uri salvate.
    """
    if not vlans:
        return 0
    saved = 0
    try:
        with app.app_context():
            from app import db
            from app.models import DiscoveredVLAN

            # Dezactivăm toate VLAN-urile existente (vor fi reactivate dacă redescoperite)
            DiscoveredVLAN.query.update({'is_active': False})

            for v in vlans:
                vlan_id = v.get('vlan_id')
                subnet = v.get('subnet')
                if not vlan_id:
                    continue
                existing = DiscoveredVLAN.query.filter_by(vlan_id=vlan_id).first()
                if existing:
                    existing.subnet = subnet or existing.subnet
                    existing.name = v.get('name') or existing.name
                    existing.interface = v.get('interface') or existing.interface
                    existing.is_active = True
                else:
                    new_vlan = DiscoveredVLAN(
                        vlan_id=vlan_id,
                        subnet=subnet,
                        name=v.get('name'),
                        interface=v.get('interface'),
                        is_active=True,
                    )
                    db.session.add(new_vlan)
                saved += 1

            db.session.commit()

            # Invalidăm cache-ul VLAN din sniffer
            try:
                from app.ids.sniffer import invalidate_vlan_cache
                invalidate_vlan_cache()
            except Exception:
                pass

    except Exception as e:
        print(f"[AutoDiscovery] Eroare la salvarea VLAN-urilor: {e}")

    return saved


def _save_devices_to_db(devices: list[dict], app) -> int:
    """Salvează dispozitivele descoperite în baza de date.

    Nu suprascrie tipurile de dispozitive existente deja clasificate manual.
    Returnează numărul de dispozitive salvate/actualizate.
    """
    if not devices:
        return 0
    saved = 0
    try:
        with app.app_context():
            from app import db
            from app.models import NetworkDevice
            from app.ids.sniffer import _FIXED_DEVICE_TYPES, _get_vlan_from_ip

            for dev in devices:
                ip = dev['ip']
                try:
                    device = NetworkDevice.query.filter_by(ip_address=ip).first()
                    if device:
                        if dev.get('mac') and not device.mac_address:
                            device.mac_address = dev['mac']
                        if dev.get('hostname') and not device.hostname:
                            device.hostname = dev['hostname']
                        device.last_seen = datetime.now(timezone.utc)
                        # Nu suprascriem tipul fix al dispozitivelor deja clasificate
                        if device.device_type not in _FIXED_DEVICE_TYPES or device.device_type == 'unknown':
                            device.device_type = dev['device_type']
                        if dev.get('comment'):
                            device.is_known = True
                    else:
                        vlan = _get_vlan_from_ip(ip)
                        device = NetworkDevice(
                            ip_address=ip,
                            mac_address=dev.get('mac'),
                            hostname=dev.get('hostname'),
                            device_type=dev['device_type'],
                            is_known=bool(dev.get('comment')),
                            vlan=str(vlan) if vlan is not None else None,
                            first_seen=datetime.now(timezone.utc),
                            last_seen=datetime.now(timezone.utc),
                        )
                        db.session.add(device)
                    saved += 1
                except Exception as e:
                    print(f"[AutoDiscovery] Eroare la salvarea dispozitivului {ip}: {e}")
                    db.session.rollback()
                    continue

            db.session.commit()

            # Invalidăm cache-ul device types din sniffer
            try:
                from app.ids.sniffer import invalidate_device_type_cache
                invalidate_device_type_cache()
            except Exception:
                pass

    except Exception as e:
        print(f"[AutoDiscovery] Eroare la salvarea dispozitivelor: {e}")

    return saved


def run_discovery(app, mikrotik_client):
    """Execută procesul complet de auto-descoperire în thread-ul curent.

    Actualizează _discovery_state pe parcurs pentru a permite monitorizarea
    progresului din interfața web.
    """
    _update_state(
        running=True,
        progress=0,
        step='Inițializare...',
        vlans_found=0,
        devices_found=0,
        completed=False,
        error=None,
        started_at=datetime.now(timezone.utc).isoformat(),
        finished_at=None,
    )
    try:
        # Pas 1: Descoperire VLAN-uri
        _update_state(step='Interogare VLAN-uri din RouterOS...', progress=10)
        vlans = _discover_vlans(mikrotik_client)
        _update_state(progress=30, vlans_found=len(vlans))

        # Pas 2: Salvare VLAN-uri
        _update_state(step=f'Salvare {len(vlans)} VLAN-uri în baza de date...', progress=35)
        saved_vlans = _save_vlans_to_db(vlans, app)

        # Pas 3: Descoperire dispozitive
        _update_state(step='Scanare dispozitive (ARP + DHCP)...', progress=40)
        devices = _discover_devices(mikrotik_client)
        _update_state(progress=70, devices_found=len(devices))

        # Pas 4: Salvare dispozitive
        _update_state(step=f'Clasificare și salvare {len(devices)} dispozitive...', progress=75)
        saved_devices = _save_devices_to_db(devices, app)

        # Pas 5: Marcare setup complet
        _update_state(step='Finalizare configurare...', progress=90)
        try:
            with app.app_context():
                from app import db
                from app.models import NetworkConfig
                cfg = NetworkConfig.query.filter_by(key='setup_complete').first()
                if cfg is None:
                    cfg = NetworkConfig(key='setup_complete', value='true')
                    db.session.add(cfg)
                else:
                    cfg.value = 'true'
                db.session.commit()
        except Exception as e:
            print(f"[AutoDiscovery] Eroare la marcarea setup-ului ca finalizat: {e}")

        _update_state(
            running=False,
            progress=100,
            step=f'Auto-descoperire finalizată: {saved_vlans} VLAN-uri, {saved_devices} dispozitive.',
            completed=True,
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        print(f"[AutoDiscovery] Finalizat: {saved_vlans} VLAN-uri, {saved_devices} dispozitive.")

    except Exception as e:
        _update_state(
            running=False,
            progress=0,
            step='Eroare la auto-descoperire.',
            error=str(e),
            completed=False,
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        print(f"[AutoDiscovery] Eroare: {e}")


def start_discovery_async(app, mikrotik_client):
    """Pornește procesul de auto-descoperire într-un thread de background.

    Returnează imediat; progresul poate fi monitorizat via get_discovery_state().
    """
    state = get_discovery_state()
    if state['running']:
        print("[AutoDiscovery] Procesul de descoperire rulează deja.")
        return

    thread = threading.Thread(
        target=run_discovery,
        args=(app, mikrotik_client),
        daemon=True,
        name='auto-discovery',
    )
    thread.start()
