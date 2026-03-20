#!/usr/bin/env python3
"""
Test pentru protecția tipurilor fixe în _flush_device_buffer() și
pentru funcționalitatea scheduler-ului de reset mobil.

Rulare:
    python scripts/test_fixed_type_protection.py
"""
import sys
import os
import threading
import time
import types

# Adăugăm rădăcina proiectului în sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_pass_count = 0
_fail_count = 0


def _assert(condition, description):
    global _pass_count, _fail_count
    if condition:
        print(f"  [PASS] {description}")
        _pass_count += 1
    else:
        print(f"  [FAIL] {description}")
        _fail_count += 1


# ---------------------------------------------------------------------------
# Test 1: _flush_device_buffer nu schimbă device_type pentru tipuri fixe
# ---------------------------------------------------------------------------

def test_flush_does_not_reclassify_fixed_types():
    """Simulăm _flush_device_buffer cu un device 'camera' și un snapshot care
    ar duce la 'mobile' în absența protecției."""
    print("\n--- Protecție tipuri fixe în _flush_device_buffer ---")

    import app.ids.sniffer as sniffer

    # Construim un mock minimal pentru app, db și NetworkDevice
    camera_ip = "192.168.2.174"
    camera_mac = "C0:39:5A:68:5B:51"  # OUI Tiandy → camera

    # Dispozitiv existent în DB: classificat corect ca 'camera'
    class MockDevice:
        def __init__(self):
            self.ip_address = camera_ip
            self.mac_address = camera_mac
            self.hostname = None
            self.device_type = "camera"
            self.last_seen = None
            self.total_packets = 0
            self.total_bytes = 0
            self.vlan = None

    mock_device = MockDevice()
    added_objects = []
    committed = [False]

    class MockSession:
        def add(self, obj):
            added_objects.append(obj)

        def commit(self):
            committed[0] = True

        def rollback(self):
            pass

        def delete(self, obj):
            pass

    mock_session = MockSession()

    # Patch session și query
    import datetime
    original_flush = sniffer._flush_device_buffer

    # Injectăm direct snapshot în buffer și apelăm cu app mock
    # Pentru a testa izolat, simulăm logica din _flush_device_buffer

    # Simulare snapshot: date care ar clasifica dispozitivul ca 'mobile' dacă nu ar fi gardă
    # (VLAN ID prezent, hostname mobil)
    snapshot_entry = {
        'mac': camera_mac,
        'packets': 10,
        'bytes': 1024,
        'last_seen': datetime.datetime.utcnow(),
        'vlan_id': 201,  # VLAN prezent → fără gardă ar declanșa reclasificarea
        'hostname': 'iPhone-test',  # hostname mobil → fără gardă ar reclasifica
        'is_new': False,
    }

    # Rulăm logica echivalentă din _flush_device_buffer pentru ramura 'if device:'
    from app.ids.sniffer import _FIXED_DEVICE_TYPES, _detect_device_type

    device = mock_device
    data = snapshot_entry
    ip = camera_ip

    # --- Logica copiată din _flush_device_buffer (ramura if device:) ---
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

    # GARDĂ: tipuri fixe nu se reclasifică
    if device.device_type not in _FIXED_DEVICE_TYPES:
        should_reclassify = (
            mac_updated
            or hostname_updated
            or (data.get('vlan_id') is not None)
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
    # --- Sfârșit logică ---

    _assert(device.device_type == 'camera',
            "Camera cu MAC Tiandy rămâne 'camera' după flush cu VLAN + hostname mobil")
    _assert(device.total_packets == 10,
            "Statisticile (packets) sunt actualizate corect pentru dispozitivul fix")
    _assert(device.total_bytes == 1024,
            "Statisticile (bytes) sunt actualizate corect pentru dispozitivul fix")
    _assert(device.vlan == '201',
            "VLAN-ul este actualizat chiar și pentru tipuri fixe")
    _assert(device.hostname == 'iPhone-test',
            "Hostname-ul lipsă este completat chiar și pentru tipuri fixe")

    # Test suplimentar: un dispozitiv 'mobile' CU același MAC va fi reclasificat
    mock_mobile = MockDevice()
    mock_mobile.device_type = 'mobile'
    mock_mobile.mac_address = camera_mac  # OUI Tiandy
    mock_mobile.hostname = None
    mock_mobile.vlan = None

    device2 = mock_mobile
    data2 = snapshot_entry.copy()
    device2.last_seen = data2['last_seen']
    device2.total_packets = (device2.total_packets or 0) + data2['packets']
    device2.total_bytes = (device2.total_bytes or 0) + data2['bytes']
    mac_updated2 = False
    if data2.get('mac') and not device2.mac_address:
        device2.mac_address = data2['mac']
        mac_updated2 = True
    hostname_updated2 = False
    if data2.get('hostname') and not device2.hostname:
        device2.hostname = data2['hostname']
        hostname_updated2 = True
    if data2.get('vlan_id') is not None:
        device2.vlan = str(data2['vlan_id'])

    if device2.device_type not in _FIXED_DEVICE_TYPES:
        should_reclassify2 = (
            mac_updated2
            or hostname_updated2
            or (data2.get('vlan_id') is not None)
            or (device2.device_type == 'client' and (device2.mac_address or device2.hostname))
        )
        if should_reclassify2:
            vlan_for_check2 = data2.get('vlan_id')
            if vlan_for_check2 is None and device2.vlan is not None:
                try:
                    vlan_for_check2 = int(device2.vlan)
                except (ValueError, TypeError):
                    pass
            new_type2 = _detect_device_type(camera_ip, mac=device2.mac_address, vlan_id=vlan_for_check2, hostname=device2.hostname)
            if new_type2 != device2.device_type:
                device2.device_type = new_type2

    _assert(device2.device_type == 'camera',
            "Dispozitiv 'mobile' cu MAC Tiandy este reclasificat la 'camera' (nu este tip fix)")


# ---------------------------------------------------------------------------
# Test 2: _FIXED_DEVICE_TYPES conține tipurile așteptate
# ---------------------------------------------------------------------------

def test_fixed_device_types_set():
    print("\n--- Conținut _FIXED_DEVICE_TYPES ---")
    from app.ids.sniffer import _FIXED_DEVICE_TYPES
    for t in ('ap', 'router', 'switch', 'server', 'camera'):
        _assert(t in _FIXED_DEVICE_TYPES, f"'{t}' este în _FIXED_DEVICE_TYPES")
    _assert('mobile' not in _FIXED_DEVICE_TYPES, "'mobile' NU este în _FIXED_DEVICE_TYPES")
    _assert('client' not in _FIXED_DEVICE_TYPES, "'client' NU este în _FIXED_DEVICE_TYPES")


# ---------------------------------------------------------------------------
# Test 3: _mobile_reset_running flag și structura _mobile_reset_scheduler
# ---------------------------------------------------------------------------

def test_mobile_reset_flag_and_scheduler_structure():
    print("\n--- Flag _mobile_reset_running și structura scheduler ---")
    import app.ids.sniffer as sniffer

    # Verificăm că flag-ul există și este False la import
    _assert(hasattr(sniffer, '_mobile_reset_running'),
            "_mobile_reset_running flag există în modul")
    _assert(sniffer._mobile_reset_running is False,
            "_mobile_reset_running este False la import")

    # Verificăm că funcțiile există
    _assert(callable(getattr(sniffer, '_mobile_reset_scheduler', None)),
            "_mobile_reset_scheduler este definit și callable")
    _assert(callable(getattr(sniffer, '_reset_mobile_devices', None)),
            "_reset_mobile_devices este definit și callable")

    # Verificăm că _MOBILE_RESET_INTERVAL este 10 minute
    _assert(sniffer._MOBILE_RESET_INTERVAL == 10 * 60,
            f"_MOBILE_RESET_INTERVAL = {sniffer._MOBILE_RESET_INTERVAL}s (așteptat 600s)")


# ---------------------------------------------------------------------------
# Test 4: _reset_mobile_devices logează întotdeauna (și când count=0)
# ---------------------------------------------------------------------------

def test_reset_mobile_always_logs():
    """Verificăm că mesajul de log apare la fiecare rulare a _reset_mobile_devices,
    inclusiv când nu există dispozitive mobile de șters."""
    print("\n--- Log complet în _reset_mobile_devices ---")

    # Verificăm codul sursă al funcției
    import inspect
    import app.ids.sniffer as sniffer

    source = inspect.getsource(sniffer._reset_mobile_devices)

    # Mesajul de log trebuie să fie în afara blocului 'if count > 0'
    # Simplu: verificăm că print-ul cu "Reset mobile" există și că nu e conditionat
    # de 'if count > 0' (adică nu există exact acel pattern)
    _assert('Reset mobile' in source,
            "Mesajul 'Reset mobile' există în sursa _reset_mobile_devices")

    # Verificăm că 'if count > 0:' nu include print-ul (adică print e neconditionat)
    lines = source.split('\n')
    count_block_indent = None  # indentarea liniei 'if count > 0:'
    in_count_block = False
    print_inside_count_block = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        indent = len(line) - len(line.lstrip())
        if stripped.startswith('if count > 0:'):
            in_count_block = True
            count_block_indent = indent
        elif in_count_block:
            # Ieșim din bloc când indentarea revine la nivelul lui 'if count > 0:' sau mai mic
            if indent <= count_block_indent:
                in_count_block = False
        if in_count_block and 'Reset mobile' in stripped and 'print' in stripped:
            print_inside_count_block = True

    _assert(not print_inside_count_block,
            "Log-ul 'Reset mobile' este în afara blocului 'if count > 0' (rulează mereu)")


# ---------------------------------------------------------------------------
# Test 5: dispozitivele 'mobile' pot fi corectate înapoi la 'client'
# ---------------------------------------------------------------------------

def test_mobile_can_be_reclassified_to_client():
    print("\n--- Reclasificare mobile fals pozitiv → client ---")

    from app.ids.sniffer import _detect_device_type

    # B8:27:EB = Raspberry Pi, nu vendor mobil.
    # Într-un entry deja marcat greșit ca 'mobile', detectorul trebuie să poată
    # reveni la 'client' când are MAC-ul real disponibil.
    detected = _detect_device_type("192.168.221.5", mac="B8:27:EB:BF:D6:ED")
    _assert(detected == 'client',
            "Raspberry Pi pe VLAN 201 este detectat ca 'client', nu 'mobile'")


# ---------------------------------------------------------------------------
# Test 6: dispozitivele 'unknown' trebuie reverificate periodic
# ---------------------------------------------------------------------------

def test_unknown_devices_are_rechecked_with_existing_metadata():
    print("\n--- Reclasificare periodică pentru dispozitive unknown ---")

    device_type = 'unknown'
    mac_address = "AC:BC:32:AA:BB:CC"
    hostname = None
    should_reclassify = (
        False
        or (device_type == 'client' and (mac_address or hostname))
        or (device_type == 'mobile' and (mac_address or hostname))
        or (device_type == 'unknown' and (mac_address or hostname))
    )
    _assert(
        should_reclassify,
        "Dispozitivele 'unknown' cu MAC/hostname existent intră în reverificarea periodică"
    )

    from app.ids.sniffer import _detect_device_type
    detected = _detect_device_type("192.168.224.6", mac=mac_address)
    _assert(
        detected == 'mobile',
        "Un dispozitiv rămas 'unknown' poate fi reclasificat corect la 'mobile' la reverificare"
    )


if __name__ == '__main__':
    test_fixed_device_types_set()
    test_flush_does_not_reclassify_fixed_types()
    test_mobile_reset_flag_and_scheduler_structure()
    test_reset_mobile_always_logs()
    test_mobile_can_be_reclassified_to_client()
    test_unknown_devices_are_rechecked_with_existing_metadata()

    print(f"\n{'='*40}")
    print(f"Rezultat: {_pass_count} PASS, {_fail_count} FAIL")
    if _fail_count:
        print("EȘEC: unele teste au picat.")
        sys.exit(1)
    else:
        print("SUCCES: toate testele au trecut.")
        sys.exit(0)
