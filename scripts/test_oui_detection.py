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

from app.ids.sniffer import normalize_mac, get_mac_oui, _looks_like_ap, _looks_like_mobile, _looks_like_camera, _detect_device_type, _is_randomized_mac, _hostname_suggests_mobile

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
    # Mobile - Apple OUI → mobile
    _assert(_detect_device_type("192.168.2.100", mac="AC:BC:32:AA:BB:CC") == 'mobile',
            "Apple OUI → mobile")
    # Mobile - Samsung OUI → mobile
    _assert(_detect_device_type("192.168.2.101", mac="34:23:BA:11:22:33") == 'mobile',
            "Samsung OUI → mobile")
    # Mobile - Xiaomi OUI → mobile
    _assert(_detect_device_type("192.168.2.102", mac="98:FA:E3:AA:BB:CC") == 'mobile',
            "Xiaomi OUI → mobile")
    # Mobile - Huawei OUI → mobile
    _assert(_detect_device_type("192.168.2.103", mac="D4:12:43:11:22:33") == 'mobile',
            "Huawei OUI → mobile")
    # Apple OUI dar IP este server → server (IP hardcodat are prioritate față de OUI mobil)
    _assert(_detect_device_type("192.168.2.241", mac="AC:BC:32:AA:BB:CC") == 'server',
            "Apple OUI dar IP server → server (IP are prioritate)")
    # Apple OUI pe subnet VLAN dar fara OUI AP → mobile (nu AP)
    _assert(_detect_device_type("192.168.221.5", mac="AC:BC:32:AA:BB:CC") == 'mobile',
            "Apple OUI pe subnet VLAN (fara OUI AP) → mobile")


def test_looks_like_mobile():
    print("\n--- _looks_like_mobile ---")
    # Apple iPhone/iPad OUI → mobile
    _assert(_looks_like_mobile("AC:BC:32:AA:BB:CC"), "Apple OUI → mobile")
    _assert(_looks_like_mobile("98:01:A7:11:22:33"), "Apple OUI 98:01:A7 → mobile")
    # Samsung mobile OUI → mobile
    _assert(_looks_like_mobile("34:23:BA:AA:BB:CC"), "Samsung OUI → mobile")
    _assert(_looks_like_mobile("6C:B7:F4:11:22:33"), "Samsung OUI 6C:B7:F4 → mobile")
    # Xiaomi OUI → mobile
    _assert(_looks_like_mobile("98:FA:E3:AA:BB:CC"), "Xiaomi OUI → mobile")
    # OnePlus OUI → mobile
    _assert(_looks_like_mobile("94:65:2D:AA:BB:CC"), "OnePlus OUI → mobile")
    # Huawei OUI → mobile
    _assert(_looks_like_mobile("D4:12:43:AA:BB:CC"), "Huawei OUI → mobile")
    # OPPO OUI → mobile
    _assert(_looks_like_mobile("94:87:E0:AA:BB:CC"), "OPPO OUI → mobile")
    # Vivo OUI → mobile
    _assert(_looks_like_mobile("88:43:E1:AA:BB:CC"), "Vivo OUI → mobile")
    # Motorola mobile OUI → mobile
    _assert(_looks_like_mobile("40:78:A8:AA:BB:CC"), "Motorola OUI → mobile")
    # TP-Link OUI → NU mobile (este AP vendor)
    _assert(not _looks_like_mobile("EC:08:6B:AA:BB:CC"), "TP-Link OUI → NU mobile")
    # ASUS OUI → NU mobile (este AP vendor)
    _assert(not _looks_like_mobile("74:D0:2B:11:22:33"), "ASUS OUI → NU mobile")
    # Vendor necunoscut → NU mobile
    _assert(not _looks_like_mobile("AA:BB:CC:DD:EE:FF"), "Vendor necunoscut → NU mobile")
    # Fara MAC → NU mobile
    _assert(not _looks_like_mobile(None), "Fara MAC → NU mobile")
    _assert(not _looks_like_mobile(""), "MAC gol → NU mobile")


def test_is_randomized_mac():
    print("\n--- _is_randomized_mac ---")
    # LAA bit setat (bit 1 al primului octet)
    _assert(_is_randomized_mac("2A:11:22:33:44:55"), "2A:xx → randomizat")
    _assert(_is_randomized_mac("6E:11:22:33:44:55"), "6E:xx → randomizat")
    _assert(_is_randomized_mac("BE:11:22:33:44:55"), "BE:xx → randomizat")
    _assert(_is_randomized_mac("DA:11:22:33:44:55"), "DA:xx → randomizat")
    # LAA bit nesetat (MAC real)
    _assert(not _is_randomized_mac("AC:BC:32:AA:BB:CC"), "Apple OUI real → NU randomizat")
    _assert(not _is_randomized_mac("EC:08:6B:AA:BB:CC"), "TP-Link OUI real → NU randomizat")
    # Edge cases
    _assert(not _is_randomized_mac(None), "None → NU randomizat")
    _assert(not _is_randomized_mac(""), "MAC gol → NU randomizat")


def test_hostname_suggests_mobile():
    print("\n--- _hostname_suggests_mobile ---")
    # Hostname-uri tipice de telefoane
    _assert(_hostname_suggests_mobile("iPhone-lui-Ion"), "iPhone hostname → mobile")
    _assert(_hostname_suggests_mobile("Galaxy-S24"), "Galaxy hostname → mobile")
    _assert(_hostname_suggests_mobile("android-device"), "android hostname → mobile")
    _assert(_hostname_suggests_mobile("SAMSUNG-SM-A346"), "Samsung SM hostname → mobile")
    _assert(_hostname_suggests_mobile("Xiaomi-Redmi-Note"), "Xiaomi Redmi hostname → mobile")
    _assert(_hostname_suggests_mobile("Pixel-6a"), "Pixel hostname → mobile")
    _assert(_hostname_suggests_mobile("OnePlus9Pro"), "OnePlus hostname → mobile")
    _assert(_hostname_suggests_mobile("huawei-p30"), "Huawei hostname → mobile")
    # Hostname-uri non-mobile
    _assert(not _hostname_suggests_mobile("DESKTOP-ABC123"), "Desktop hostname → NU mobile")
    _assert(not _hostname_suggests_mobile("laptop-john"), "Laptop hostname → NU mobile")
    _assert(not _hostname_suggests_mobile(None), "None → NU mobile")
    _assert(not _hostname_suggests_mobile(""), "String gol → NU mobile")


def test_detect_device_type_extended():
    print("\n--- _detect_device_type (metode noi) ---")
    # Detectare pe baza hostname-ului
    _assert(_detect_device_type("192.168.221.10", hostname="iPhone-lui-Ion") == 'mobile',
            "Hostname iPhone pe subnet VLAN → mobile")
    _assert(_detect_device_type("192.168.2.100", hostname="Galaxy-S24") == 'mobile',
            "Hostname Galaxy pe subnet non-VLAN → mobile")
    # MAC randomizat pe subnet VLAN → mobile
    _assert(_detect_device_type("192.168.221.10", mac="2A:11:22:33:44:55") == 'mobile',
            "MAC randomizat pe subnet VLAN → mobile")
    # MAC randomizat pe subnet non-VLAN (192.168.2.x) → client (nu VLAN)
    _assert(_detect_device_type("192.168.2.100", mac="2A:11:22:33:44:55") == 'client',
            "MAC randomizat pe subnet non-VLAN → client")
    # IP hardcodat are prioritate față de hostname
    _assert(_detect_device_type("192.168.2.1", hostname="iPhone-test") == 'router',
            "IP router cu hostname iPhone → router (IP are prioritate)")
    # AP OUI are prioritate față de hostname
    _assert(_detect_device_type("192.168.221.5", mac="EC:08:6B:AA:BB:CC", hostname="Galaxy-S24") == 'ap',
            "TP-Link OUI + VLAN + hostname Galaxy → ap (OUI AP are prioritate)")


def test_new_mobile_vendors():
    print("\n--- OUI producători noi (Realme, Nokia, Poco, Honor, Lenovo, Google) ---")
    # Realme OUI → mobile
    _assert(_looks_like_mobile("44:D4:E0:AA:BB:CC"), "Realme OUI 44:D4:E0 → mobile")
    _assert(_looks_like_mobile("DC:44:27:11:22:33"), "Realme OUI DC:44:27 → mobile")
    _assert(_detect_device_type("192.168.2.110", mac="44:D4:E0:AA:BB:CC") == 'mobile',
            "Realme OUI → detect mobile")
    # Nokia OUI → mobile
    _assert(_looks_like_mobile("84:C7:EA:AA:BB:CC"), "Nokia OUI 84:C7:EA → mobile")
    _assert(_looks_like_mobile("F0:7D:68:11:22:33"), "Nokia OUI F0:7D:68 → mobile")
    _assert(_detect_device_type("192.168.2.111", mac="84:C7:EA:AA:BB:CC") == 'mobile',
            "Nokia OUI → detect mobile")
    # Poco OUI → mobile
    _assert(_looks_like_mobile("5C:E8:B8:AA:BB:CC"), "Poco OUI 5C:E8:B8 → mobile")
    _assert(_looks_like_mobile("BC:32:B2:11:22:33"), "Poco OUI BC:32:B2 → mobile")
    _assert(_detect_device_type("192.168.2.112", mac="5C:E8:B8:AA:BB:CC") == 'mobile',
            "Poco OUI → detect mobile")
    # Honor OUI → mobile
    _assert(_looks_like_mobile("4C:99:E3:AA:BB:CC"), "Honor OUI 4C:99:E3 → mobile")
    _assert(_looks_like_mobile("F4:9F:54:11:22:33"), "Honor OUI F4:9F:54 → mobile")
    _assert(_detect_device_type("192.168.2.113", mac="4C:99:E3:AA:BB:CC") == 'mobile',
            "Honor OUI → detect mobile")
    # Lenovo OUI → mobile
    _assert(_looks_like_mobile("84:DB:AC:AA:BB:CC"), "Lenovo OUI 84:DB:AC → mobile")
    _assert(_looks_like_mobile("F4:63:1F:11:22:33"), "Lenovo OUI F4:63:1F → mobile")
    _assert(_detect_device_type("192.168.2.114", mac="84:DB:AC:AA:BB:CC") == 'mobile',
            "Lenovo OUI → detect mobile")
    # Google Pixel OUI → mobile
    _assert(_looks_like_mobile("94:B4:0F:AA:BB:CC"), "Google OUI 94:B4:0F → mobile")
    _assert(_looks_like_mobile("F0:27:2D:11:22:33"), "Google OUI F0:27:2D → mobile")
    _assert(_detect_device_type("192.168.2.115", mac="94:B4:0F:AA:BB:CC") == 'mobile',
            "Google Pixel OUI → detect mobile")


def test_real_world_hostnames():
    print("\n--- Teste hostname-uri reale din rețea ---")
    # Cazuri concrete din traficul școlii
    _assert(_hostname_suggests_mobile("POCO-F7-Pro"), "POCO-F7-Pro → mobile")
    _assert(_hostname_suggests_mobile("S24-al-utilizatorului-Beatrice"), "S24-al-... → mobile")
    _assert(_hostname_suggests_mobile("Galaxy-A12"), "Galaxy-A12 → mobile")
    _assert(_hostname_suggests_mobile("Galaxy-S24"), "Galaxy-S24 → mobile")
    _assert(_hostname_suggests_mobile("POCO-X3-NFC"), "POCO-X3-NFC → mobile")
    _assert(_hostname_suggests_mobile("A52s-telefon"), "A52s → mobile")

    # _detect_device_type cu hostname pe subnet VLAN
    _assert(
        _detect_device_type("192.168.227.7", mac="92:3B:61:49:66:3D", hostname="POCO-F7-Pro") == 'mobile',
        "POCO-F7-Pro pe 192.168.227.x (VLAN) cu MAC randomizat → mobile"
    )
    _assert(
        _detect_device_type("192.168.227.9", mac="2A:01:35:FC:45:3D", hostname="S24-al-utilizatorului-Beatrice") == 'mobile',
        "S24-al-... pe 192.168.227.x (VLAN) cu MAC randomizat → mobile"
    )
    _assert(
        _detect_device_type("192.168.224.6", mac="AA:C5:E1:BA:08:FA", hostname="Galaxy-A12") == 'mobile',
        "Galaxy-A12 pe 192.168.224.x (VLAN) cu MAC randomizat → mobile"
    )


def test_camera_oui_detection():
    print("\n--- OUI camere de supraveghere (Kedacom/Tiandy/NVR) ---")
    # Kedacom KM-IP531D-K OUI → camera
    _assert(_looks_like_camera("E0:61:B2:63:A9:DA"), "Kedacom OUI E0:61:B2 → camera")
    _assert(_looks_like_camera("E0:61:B2:63:A9:E0"), "Kedacom OUI E0:61:B2 (a doua cameră) → camera")
    # Tiandy/Kedacom 7L09F12 OUI → camera
    _assert(_looks_like_camera("C0:39:5A:68:5B:51"), "Tiandy OUI C0:39:5A → camera")
    _assert(_looks_like_camera("C0:39:5A:68:58:D2"), "Tiandy OUI C0:39:5A (Sala Sport) → camera")
    _assert(_looks_like_camera("C0:39:5A:37:CF:B3"), "Tiandy OUI C0:39:5A (Sala Sport intrare) → camera")
    # NVR OUI → camera
    _assert(_looks_like_camera("FC:5F:49:83:39:A6"), "NVR OUI FC:5F:49 → camera")
    # Non-camera OUI → NU camera
    _assert(not _looks_like_camera("AC:BC:32:AA:BB:CC"), "Apple OUI → NU camera")
    _assert(not _looks_like_camera("EC:08:6B:AA:BB:CC"), "TP-Link OUI → NU camera")
    _assert(not _looks_like_camera(None), "Fara MAC → NU camera")
    _assert(not _looks_like_camera(""), "MAC gol → NU camera")

    # _detect_device_type cu OUI cameră → camera (chiar fără IP hardcodat)
    _assert(_detect_device_type("192.168.2.174", mac="C0:39:5A:68:5B:51") == 'camera',
            "IP .174 (range camere) cu MAC Tiandy → camera")
    _assert(_detect_device_type("192.168.2.170", mac="C0:39:5A:68:58:D2") == 'camera',
            "IP .170 cu MAC Tiandy (Sala Sport) → camera")
    _assert(_detect_device_type("192.168.2.160", mac="FC:5F:49:83:39:A6") == 'camera',
            "IP .160 (NVR) cu MAC FC:5F:49 → camera")
    _assert(_detect_device_type("192.168.2.161", mac="E0:61:B2:63:A9:DA") == 'camera',
            "IP .161 cu MAC Kedacom → camera")
    # OUI cameră pe IP arbitrar (fara hardcoding IP) → camera
    _assert(_detect_device_type("192.168.2.200", mac="C0:39:5A:68:5B:51") == 'camera',
            "IP arbitrar cu MAC Tiandy → camera (OUI are prioritate față de mobile)")
    _assert(_detect_device_type("192.168.2.200", mac="E0:61:B2:63:A9:DA") == 'camera',
            "IP arbitrar cu MAC Kedacom → camera")
    # IP hardcodat are prioritate față de OUI cameră (test compatibilitate inversă)
    _assert(_detect_device_type("192.168.2.80") == 'camera',
            "IP .80 (NVR hardcodat) fara MAC → camera")

    # Caz special: dispozitiv clasificat ca 'mobile' în DB, dar cu OUI cameră
    # _detect_device_type trebuie să returneze 'camera' → _fix_device_types îl va reclasifica
    _assert(_detect_device_type("192.168.2.174", mac="C0:39:5A:68:5B:51") == 'camera',
            "Dispozitiv mobile cu MAC Tiandy (C0:39:5A) → _detect_device_type returnează 'camera', nu 'mobile'")


if __name__ == '__main__':
    test_normalize_mac()
    test_get_mac_oui()
    test_looks_like_ap()
    test_looks_like_mobile()
    test_detect_device_type()
    test_is_randomized_mac()
    test_hostname_suggests_mobile()
    test_detect_device_type_extended()
    test_new_mobile_vendors()
    test_real_world_hostnames()
    test_camera_oui_detection()
    print(f"\n{'='*40}")
    print(f"Rezultat: {_pass_count} PASS, {_fail_count} FAIL")
    if _fail_count:
        print("EȘEC: unele teste au picat.")
        sys.exit(1)
    else:
        print("SUCCES: toate testele au trecut.")
        sys.exit(0)
