"""
Sincronizare periodică a datelor MikroTik RouterOS cu baza de date locală.
Rulează într-un thread de background la fiecare MIKROTIK_SYNC_INTERVAL secunde.
"""
import threading
import time
from datetime import datetime


def start_mikrotik_sync(app, mikrotik_client):
    """Pornește thread-ul de sincronizare MikroTik în background."""

    def _sync_loop():
        interval = app.config.get('MIKROTIK_SYNC_INTERVAL', 60)
        while True:
            try:
                _run_sync(app, mikrotik_client)
            except Exception as e:
                print(f"[MikroTik Sync] Eroare neașteptată: {e}")
            time.sleep(interval)

    thread = threading.Thread(target=_sync_loop, daemon=True, name='mikrotik-sync')
    thread.start()
    print("[MikroTik Sync] Thread de sincronizare pornit.")


def _run_sync(app, mikrotik_client):
    """Execută o rundă completă de sincronizare cu context de aplicație."""
    if not mikrotik_client.is_connected():
        return

    with app.app_context():
        from app import db
        from app.models import NetworkDevice, BlockedHostname, SecurityLog
        from app.ids.sniffer import (
            _get_vlan_from_ip,
            traffic_stats,
            _stats_lock,
            _detect_device_type,
            _FIXED_DEVICE_TYPES,
        )

        # ------------------------------------------------------------------
        # 1. Sincronizare DHCP leases → NetworkDevice
        # ------------------------------------------------------------------
        leases = mikrotik_client.get_dhcp_leases()
        for lease in leases:
            if lease.get('status') != 'bound':
                continue

            ip = lease.get('ip', '').strip()
            mac = lease.get('mac', '').strip()
            hostname = lease.get('hostname', '').strip() or None
            comment = lease.get('comment', '').strip()

            if not ip:
                continue

            device = NetworkDevice.query.filter_by(ip_address=ip).first()
            if device is None:
                device = NetworkDevice(ip_address=ip)
                db.session.add(device)

            if mac:
                device.mac_address = mac
            if hostname:
                device.hostname = hostname

            device.last_seen = datetime.utcnow()

            # VLAN din IP
            vlan = _get_vlan_from_ip(ip)
            if vlan is not None:
                device.vlan_id = vlan

            # Classificare tip dispozitiv — respectă tipurile fixe și is_known
            if device.device_type not in _FIXED_DEVICE_TYPES:
                # Nu reclasifica dispozitive cunoscute care au deja un tip specific (non-client)
                # Reclasifică doar dispozitive noi (fără tip) sau cu tip generic ('client')
                if not (device.is_known and device.device_type and device.device_type != 'client'):
                    new_type = _detect_device_type(ip, mac=mac, vlan_id=vlan, hostname=hostname)
                    if new_type:
                        device.device_type = new_type

            # Dispozitiv cunoscut dacă are comment în DHCP
            if comment:
                device.is_known = True

            # ------------------------------------------------------------------
            # Verificare hostname blocat — detectează reapariția cu MAC nou
            # ------------------------------------------------------------------
            if hostname:
                hostname_lower = hostname.lower()
                blocked_hn = BlockedHostname.query.filter_by(
                    hostname=hostname_lower, is_active=True
                ).first()
                if blocked_hn:
                    # Dispozitivul blocat a reapărut (posibil cu MAC nou)
                    new_mac = mac.upper() if mac else ''
                    old_mac = (blocked_hn.associated_mac or '').upper()
                    server = lease.get('server', '')

                    # Dacă MAC-ul s-a schimbat, blocăm noul MAC automat
                    if new_mac and new_mac != old_mac:
                        print(f"[MikroTik Sync] Hostname blocat '{hostname_lower}' detectat cu MAC nou {new_mac} pe {server}")

                        # Log eveniment
                        log = SecurityLog(
                            event_type='blocked_hostname_reappeared',
                            source_ip=ip,
                            message=(f"Dispozitiv blocat '{hostname_lower}' detectat cu MAC nou "
                                     f"{new_mac} pe {server}"),
                            severity='critical',
                        )
                        db.session.add(log)

                        # Actualizăm MAC-ul asociat în înregistrarea blocată
                        blocked_hn.associated_mac = new_mac
                        blocked_hn.associated_ip = ip
                        if server:
                            blocked_hn.dhcp_server = server

                        # Auto-block MAC nou pe bridge filter
                        try:
                            comment_block = f'SchoolSec: hostname={hostname_lower} MAC nou detectat'
                            mikrotik_client.block_mac_on_router(new_mac, comment=comment_block)
                        except Exception as e:
                            print(f"[MikroTik Sync] Eroare auto-block MAC nou {new_mac}: {e}")

                        # Notificare prin callback-uri (alertă critică)
                        try:
                            detector = getattr(app, '_ids_detector', None)
                            if detector:
                                detector._fire_alert(
                                    alert_type='blocked_hostname_reappeared',
                                    source_ip=ip,
                                    message=(f"Dispozitiv blocat '{hostname_lower}' detectat cu MAC nou "
                                             f"{new_mac} pe {server}"),
                                    severity='critical',
                                )
                        except Exception as e:
                            print(f"[MikroTik Sync] Eroare fire_alert pentru hostname reapărut: {e}")

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"[MikroTik Sync] Eroare la salvarea DHCP leases: {e}")

        # ------------------------------------------------------------------
        # 2. Completare MAC-uri lipsă din tabela ARP
        # ------------------------------------------------------------------
        arp_table = mikrotik_client.get_arp_table()
        arp_map = {entry['ip']: entry['mac'] for entry in arp_table if entry.get('ip') and entry.get('mac')}

        if arp_map:
            devices_without_mac = NetworkDevice.query.filter(
                (NetworkDevice.mac_address.is_(None)) | (NetworkDevice.mac_address == '')
            ).all()
            updated = False
            for device in devices_without_mac:
                mac = arp_map.get(device.ip_address)
                if mac:
                    device.mac_address = mac
                    updated = True
            if updated:
                try:
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    print(f"[MikroTik Sync] Eroare la actualizarea ARP: {e}")

        # ------------------------------------------------------------------
        # 3. Actualizare traffic_stats cu protocoalele din firewall connections
        # ------------------------------------------------------------------
        connections = mikrotik_client.get_active_connections()
        if connections:
            with _stats_lock:
                for conn in connections:
                    proto = conn.get('protocol', '').strip().upper()
                    if proto:
                        traffic_stats['protocols'][proto] += 1

        print(f"[MikroTik Sync] Sincronizare completă: {len(leases)} lease-uri, "
              f"{len(arp_table)} ARP, {len(connections)} conexiuni.")

        # ------------------------------------------------------------------
        # 4. Monitorizare securitate externă
        # ------------------------------------------------------------------
        external_monitor = getattr(app, '_external_monitor', None)
        if external_monitor:
            try:
                external_monitor.run_check()
            except Exception as e:
                print(f"[ExternalMonitor] Eroare în run_check: {e}")
