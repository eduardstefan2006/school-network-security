"""
Auto-configurare IDS pe baza topologiei descoperite.

Detectează interfețele disponibile din RouterOS și configurează
sniffer-ul pentru monitorizare optimă a rețelei descoperite.
"""
import ipaddress


def get_sniffer_interfaces(mikrotik_client) -> list[str]:
    """Returnează lista interfețelor potrivite pentru captură de pachete.

    Interogează RouterOS pentru interfețele active și le filtrează
    pe cele relevante pentru monitorizare (exclude loopback, inactive).

    Returns:
        Lista de nume de interfețe (ex: ['ether1', 'bridge-lan', ...])
    """
    interfaces = []
    if mikrotik_client is None or not mikrotik_client.is_connected():
        return interfaces

    try:
        conn = mikrotik_client._connection
        for item in conn('/interface/print'):
            name = item.get('name', '')
            iface_type = item.get('type', '')
            running = item.get('running', 'false')
            disabled = item.get('disabled', 'false')

            if not name:
                continue
            # Excludem interfețele inactive sau dezactivate
            if running == 'false' or disabled == 'true':
                continue
            # Excludem loopback
            if iface_type == 'loopback' or name == 'lo':
                continue
            interfaces.append(name)
    except Exception as e:
        print(f"[IDSConfig] Eroare la obținerea interfețelor: {e}")

    return interfaces


def get_wan_interface(mikrotik_client) -> str | None:
    """Detectează interfața WAN (conexiunea la internet) din RouterOS.

    Caută reguli NAT masquerade sau rute default pentru a identifica WAN.

    Returns:
        Numele interfeței WAN sau None dacă nu poate fi detectată.
    """
    if mikrotik_client is None or not mikrotik_client.is_connected():
        return None

    try:
        conn = mikrotik_client._connection
        # Căutăm ruta default pentru a identifica WAN
        for item in conn('/ip/route/print'):
            dst = item.get('dst-address', '')
            gateway = item.get('gateway', '')
            if dst == '0.0.0.0/0' and gateway:
                # Găsim interfața pe care este gateway-ul
                for iface in conn('/ip/address/print'):
                    network = iface.get('network', '')
                    iface_name = iface.get('interface', '')
                    try:
                        parts = iface.get('address', '').split('/')
                        net = ipaddress.ip_network(parts[0] + '/' + parts[1], strict=False)
                        gw = ipaddress.ip_address(gateway)
                        if gw in net:
                            return iface_name
                    except (ValueError, IndexError):
                        continue
    except Exception as e:
        print(f"[IDSConfig] Eroare la detectarea WAN: {e}")

    return None


def configure_ids_for_network(app):
    """Configurează IDS-ul pe baza topologiei descoperite din baza de date.

    Citește VLAN-urile și dispozitivele descoperite și actualizează
    configurația sniffer-ului corespunzător.
    """
    try:
        with app.app_context():
            from app.ids.sniffer import invalidate_vlan_cache, invalidate_device_type_cache
            invalidate_vlan_cache()
            invalidate_device_type_cache()
            print("[IDSConfig] Cache-urile sniffer au fost invalidate. IDS reconfigurat.")
    except Exception as e:
        print(f"[IDSConfig] Eroare la configurarea IDS: {e}")
