#!/usr/bin/env python3
"""
Teste pentru detecția automată a dispozitivelor non-mobile pe baza OUI.

Rulare:
    python scripts/test_client_vendor_detection.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ids.sniffer import _looks_like_client_device, _detect_device_type

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


def test_client_vendor_ouis():
    print("\n--- OUI non-mobile / client ---")
    _assert(_looks_like_client_device("B8:27:EB:BF:D6:ED"), "Raspberry Pi OUI → client")
    _assert(_looks_like_client_device("DC:CD:2F:86:4F:15"), "Epson OUI → client")
    _assert(_looks_like_client_device("40:C2:BA:70:6B:56"), "Compal OUI → client")
    _assert(not _looks_like_client_device("AC:BC:32:AA:BB:CC"), "Apple OUI → NU client non-mobile")


def test_detect_device_type_for_reported_devices():
    print("\n--- Dispozitive raportate din UI ---")
    _assert(_detect_device_type("192.168.221.5", mac="B8:27:EB:BF:D6:ED") == 'client',
            "192.168.221.5 Raspberry Pi → client")
    _assert(_detect_device_type("192.168.221.4", mac="DC:CD:2F:86:4F:15") == 'client',
            "192.168.221.4 Epson → client")
    _assert(_detect_device_type("192.168.231.14", mac="40:C2:BA:70:6B:56") == 'client',
            "192.168.231.14 calculator laborator → client")


if __name__ == '__main__':
    test_client_vendor_ouis()
    test_detect_device_type_for_reported_devices()

    print(f"\n{'=' * 40}")
    print(f"Rezultat: {_pass_count} PASS, {_fail_count} FAIL")
    if _fail_count:
        print("EȘEC: unele teste au picat.")
        sys.exit(1)
    print("SUCCES: toate testele au trecut.")
    sys.exit(0)
