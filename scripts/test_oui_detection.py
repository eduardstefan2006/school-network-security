#!/usr/bin/env python3
"""
Test minimal pentru logica de detecție automată a AP-urilor (OUI vendor + VLAN).

Rulare:
    python scripts/test_oui_detection.py
"""
import sys
import os

# Adăugăm rădăcina proiectului în sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ids.sniffer import normalize_mac, get_mac_oui, _looks_like_ap, _detect_device_type

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


def test_normalize_mac():
    print("\n--- normalize_mac ---")
    _assert(normalize_mac("EC:08:6B:AA:BB:CC") == "ec:08:6b:aa:bb:cc", "format standard cu ':'")
    _assert(normalize_mac("EC-08-6B-AA-BB-CC") == "ec:08:6b:aa:bb:cc", "format cu '-'")
    _assert(normalize_mac("EC086BAABBCC") == "ec:08:6b:aa:bb:cc", "fara separator")
    _assert(normalize_mac("B0.6E.BF.11.22.33") == "b0:6e:bf:11:22:33", "format cu '.'")
    _assert(normalize_mac(None) is None, "None input")
    _assert(normalize_mac("") is None, "string gol")
    _assert(normalize_mac("ZZ:ZZ:ZZ:00:11:22") is None, "caractere invalide")


def test_get_mac_oui():
    print("\n--- get_mac_oui ---")
    _assert(get_mac_oui("EC:08:6B:AA:BB:CC") == "EC:08:6B", "TP-Link OUI uppercase")
    _assert(get_mac_oui("ec:08:6b:aa:bb:cc") == "EC:08:6B", "TP-Link OUI lowercase input")
    _assert(get_mac_oui("74:D0:2B:11:22:33") == "74:D0:2B", "ASUS OUI")
    _assert(get_mac_oui("B0:6E:BF:11:22:33") == "B0:6E:BF", "ASUS OUI B0:6E:BF")
    _assert(get_mac_oui(None) is None, "None input")


def test_looks_like_ap():
    print("\n--- _looks_like_ap ---")
    # TP-Link pe VLAN → AP
    _assert(_looks_like_ap("EC:08:6B:AA:BB:CC", 201, "192.168.221.2"), "TP-Link + VLAN explicit → AP")
    # ASUS pe VLAN → AP
    _assert(_looks_like_ap("74:D0:2B:11:22:33", 205, "192.168.225.2"), "ASUS + VLAN explicit → AP")
    # TP-Link fara VLAN dar pe subnet VLAN → AP
    _assert(_looks_like_ap("50:C7:BF:AA:BB:CC", None, "192.168.222.2"), "TP-Link + subnet VLAN (fara vlan_id) → AP")
    # ASUS fara VLAN dar pe subnet VLAN → AP
    _assert(_looks_like_ap("B0:6E:BF:11:22:33", None, "192.168.232.2"), "ASUS + subnet VLAN (fara vlan_id) → AP")
    # TP-Link pe subnet non-VLAN (192.168.2.x) → NU e AP
    _assert(not _looks_like_ap("EC:08:6B:AA:BB:CC", None, "192.168.2.50"), "TP-Link + IP non-VLAN → NU AP")
    # Vendor necunoscut pe VLAN → NU e AP
    _assert(not _looks_like_ap("AA:BB:CC:DD:EE:FF", 201, "192.168.221.5"), "Vendor necunoscut + VLAN → NU AP")
    # Fara MAC → NU e AP
    _assert(not _looks_like_ap(None, 201, "192.168.221.2"), "Fara MAC → NU AP")
    _assert(not _looks_like_ap("", 201, "192.168.221.2"), "MAC gol → NU AP")


def test_detect_device_type():
    print("\n--- _detect_device_type ---")
    # AP detectat prin OUI + VLAN
    _assert(_detect_device_type("192.168.221.5", mac="EC:08:6B:AA:BB:CC", vlan_id=201) == 'ap',
            "TP-Link OUI + VLAN → ap")
    _assert(_detect_device_type("192.168.232.5", mac="74:D0:2B:11:22:33", vlan_id=212) == 'ap',
            "ASUS OUI + VLAN → ap")
    # AP detectat prin OUI + subnet VLAN (fara vlan_id explicit)
    _assert(_detect_device_type("192.168.221.2", mac="50:C7:BF:AA:BB:CC") == 'ap',
            "TP-Link OUI + subnet VLAN (fara vlan_id) → ap")
    # AP detectat prin IP hardcodat (_AP_IPS) – compatibilitate inversă
    _assert(_detect_device_type("192.168.221.2") == 'ap', "IP in _AP_IPS (fara MAC) → ap")
    # Router, switch, server, cameră – logica IP nealterată
    _assert(_detect_device_type("192.168.2.1") == 'router', "Router principal")
    _assert(_detect_device_type("192.168.2.5") == 'switch', "Switch")
    _assert(_detect_device_type("192.168.2.80") == 'camera', "Camera NVR")
    _assert(_detect_device_type("192.168.2.241") == 'server', "Server")
    # Client obisnuit
    _assert(_detect_device_type("192.168.2.100") == 'client', "Client obisnuit")
    # Vendor TP-Link dar pe subnet non-VLAN → client (nu AP)
    _assert(_detect_device_type("192.168.2.50", mac="EC:08:6B:AA:BB:CC") == 'client',
            "TP-Link OUI dar pe subnet non-VLAN → client")


if __name__ == '__main__':
    test_normalize_mac()
    test_get_mac_oui()
    test_looks_like_ap()
    test_detect_device_type()

    print(f"\n{'='*40}")
    print(f"Rezultat: {_pass_count} PASS, {_fail_count} FAIL")
    if _fail_count:
        print("EȘEC: unele teste au picat.")
        sys.exit(1)
    else:
        print("SUCCES: toate testele au trecut.")
        sys.exit(0)
