#!/usr/bin/env python3
"""
Teste de integrare minimală pentru rutele din pagina Hartă Rețea.

Rulare:
    python scripts/test_network_routes.py
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

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


def _build_app():
    db_fd, db_path = tempfile.mkstemp(prefix='schoolsec-test-', suffix='.db')
    os.close(db_fd)
    database_uri = 'sqlite:///' + db_path
    os.environ['DATABASE_URL'] = database_uri
    os.environ['MIKROTIK_ENABLED'] = 'false'
    os.environ['TELEGRAM_ENABLED'] = 'false'

    from config import config as app_config
    app_config['default'].SQLALCHEMY_DATABASE_URI = database_uri

    from app import create_app, db
    from app.models import User, NetworkConfig

    app = create_app('default')
    app.config['TESTING'] = True

    with app.app_context():
        admin = User(username='admin-test', role='admin', email='admin@test.local')
        admin.set_password('secret')
        db.session.add(admin)
        db.session.add(NetworkConfig(key='setup_complete', value='true'))
        db.session.commit()

    return app, db_path


def _login(client, user_id):
    with client.session_transaction() as session:
        session['_user_id'] = str(user_id)
        session['_fresh'] = True


def test_api_ip_connections_returns_sorted_results():
    print("\n--- /api/network/ip/<ip>/connections ---")

    app, db_path = _build_app()
    try:
        from app import db
        from app.models import User, IPConnection

        with app.app_context():
            admin = User.query.filter_by(username='admin-test').first()
            db.session.add_all([
                IPConnection(
                    source_ip='192.168.224.6',
                    hostname='facebook.com',
                    app_name='📘 Facebook',
                    bytes_total=2048,
                    packets_count=10,
                    last_seen=datetime.now(timezone.utc),
                ),
                IPConnection(
                    source_ip='192.168.224.6',
                    hostname='tiktok.com',
                    app_name='🎵 TikTok',
                    bytes_total=4096,
                    packets_count=20,
                    last_seen=datetime.now(timezone.utc),
                ),
            ])
            db.session.commit()
            admin_id = admin.id

        client = app.test_client()
        _login(client, admin_id)
        response = client.get('/api/network/ip/192.168.224.6/connections')
        data = response.get_json()

        _assert(response.status_code == 200, "Endpoint-ul conexiuni per IP răspunde cu 200")
        _assert(isinstance(data, list) and len(data) == 2, "Endpoint-ul returnează lista conexiunilor detectate")
        _assert(data[0]['hostname'] == 'tiktok.com', "Conexiunile sunt ordonate descrescător după bytes_total")
        _assert(data[0]['app_name'] == '🎵 TikTok', "app_name este returnat corect pentru UI-ul din Hartă Rețea")
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_update_device_can_remove_known_flag_without_typeerror():
    print("\n--- /api/network/device/<id>/update ---")

    app, db_path = _build_app()
    try:
        from app import db
        from app.models import User, NetworkDevice

        with app.app_context():
            admin = User.query.filter_by(username='admin-test').first()
            device = NetworkDevice(
                ip_address='192.168.224.6',
                mac_address='AC:BC:32:AA:BB:CC',
                hostname='iPhone-test',
                device_type='known',
                is_known=True,
                vlan='204',
                first_seen=datetime.now(timezone.utc) - timedelta(hours=1),
                last_seen=datetime.now(timezone.utc),
            )
            db.session.add(device)
            db.session.commit()
            admin_id = admin.id
            device_id = device.id

        client = app.test_client()
        _login(client, admin_id)
        response = client.post(
            f'/api/network/device/{device_id}/update',
            json={'is_known': False},
        )
        data = response.get_json()

        _assert(response.status_code == 200, "Update device răspunde cu 200 când se elimină flagul is_known")
        _assert(data.get('success') is True, "Update device returnează success=True")

        with app.app_context():
            updated = db.session.get(NetworkDevice, device_id)
            _assert(updated.is_known is False, "Dispozitivul nu mai este marcat drept known")
            _assert(updated.device_type == 'mobile', "Dispozitivul este reclasificat corect după eliminarea flagului known")
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_reclassify_mobile_includes_unknown_devices():
    print("\n--- /api/devices/reclassify-mobile ---")

    app, db_path = _build_app()
    try:
        from app import db
        from app.models import User, NetworkDevice

        with app.app_context():
            admin = User.query.filter_by(username='admin-test').first()
            device = NetworkDevice(
                ip_address='192.168.224.7',
                mac_address='AC:BC:32:AA:BB:CD',
                hostname='iPhone-lui-Ion',
                device_type='unknown',
                is_known=False,
                vlan='204',
                first_seen=datetime.now(timezone.utc) - timedelta(minutes=30),
                last_seen=datetime.now(timezone.utc),
            )
            db.session.add(device)
            db.session.commit()
            admin_id = admin.id
            device_id = device.id

        client = app.test_client()
        _login(client, admin_id)
        response = client.post('/api/devices/reclassify-mobile')
        data = response.get_json()

        _assert(response.status_code == 200, "Reclassify mobile răspunde cu 200")
        _assert(data.get('reclassified') == 1, "Endpoint-ul reclasifică și dispozitivele de tip unknown")

        with app.app_context():
            updated = db.session.get(NetworkDevice, device_id)
            _assert(updated.device_type == 'mobile', "Dispozitivul unknown a fost actualizat la mobile")
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_cleanup_old_ip_connections_respects_retention():
    print("\n--- _cleanup_old_ip_connections ---")

    app, db_path = _build_app()
    try:
        from app import db
        from app.models import IPConnection
        from app.ids.sniffer import _cleanup_old_ip_connections

        with app.app_context():
            db.session.add_all([
                IPConnection(
                    source_ip='192.168.224.6',
                    hostname='old.example',
                    bytes_total=100,
                    packets_count=1,
                    last_seen=datetime.now(timezone.utc) - timedelta(days=45),
                ),
                IPConnection(
                    source_ip='192.168.224.6',
                    hostname='recent.example',
                    bytes_total=200,
                    packets_count=2,
                    last_seen=datetime.now(timezone.utc) - timedelta(days=2),
                ),
            ])
            db.session.commit()

        deleted = _cleanup_old_ip_connections(app, retention_days=30)
        _assert(deleted == 1, "Curățarea retenției șterge exact intrările prea vechi")

        with app.app_context():
            remaining = {c.hostname for c in IPConnection.query.all()}
            _assert('old.example' not in remaining, "Intrarea veche a fost ștearsă din IPConnection")
            _assert('recent.example' in remaining, "Intrarea recentă a fost păstrată")
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


if __name__ == '__main__':
    test_api_ip_connections_returns_sorted_results()
    test_update_device_can_remove_known_flag_without_typeerror()
    test_reclassify_mobile_includes_unknown_devices()
    test_cleanup_old_ip_connections_respects_retention()

    print(f"\n{'='*40}")
    print(f"Rezultat: {_pass_count} PASS, {_fail_count} FAIL")
    if _fail_count:
        print("EȘEC: unele teste au picat.")
        sys.exit(1)
    else:
        print("SUCCES: toate testele au trecut.")
        sys.exit(0)
