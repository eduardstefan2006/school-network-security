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


def _utc_naive_now():
    return datetime.utcnow()


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
                    last_seen=_utc_naive_now(),
                ),
                IPConnection(
                    source_ip='192.168.224.6',
                    hostname='tiktok.com',
                    app_name='🎵 TikTok',
                    bytes_total=4096,
                    packets_count=20,
                    last_seen=_utc_naive_now(),
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
                    last_seen=_utc_naive_now() - timedelta(days=45),
                ),
                IPConnection(
                    source_ip='192.168.224.6',
                    hostname='recent.example',
                    bytes_total=200,
                    packets_count=2,
                    last_seen=_utc_naive_now() - timedelta(days=2),
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


def test_api_app_usage_returns_percentages_and_filters():
    print("\n--- /api/statistics/app-usage ---")

    app, db_path = _build_app()
    try:
        from app import db
        from app.models import User, AppTrafficStat

        today = datetime.now(timezone.utc)
        with app.app_context():
            admin = User.query.filter_by(username='admin-test').first()
            db.session.add_all([
                AppTrafficStat(
                    stat_date=today.date(),
                    source_ip='192.168.224.6',
                    hostname='facebook.com',
                    app_name='📘 Facebook',
                    bytes_total=3000,
                    packets_count=30,
                    first_seen=today - timedelta(minutes=20),
                    last_seen=today - timedelta(minutes=5),
                ),
                AppTrafficStat(
                    stat_date=today.date(),
                    source_ip='192.168.224.7',
                    hostname='tiktok.com',
                    app_name='🎵 TikTok',
                    bytes_total=7000,
                    packets_count=70,
                    first_seen=today - timedelta(minutes=18),
                    last_seen=today - timedelta(minutes=2),
                ),
            ])
            db.session.commit()
            admin_id = admin.id

        client = app.test_client()
        _login(client, admin_id)

        response = client.get('/api/statistics/app-usage?period=today')
        data = response.get_json()
        _assert(response.status_code == 200, "API-ul app-usage răspunde cu 200")
        _assert(data['summary']['total_apps'] == 2, "API-ul app-usage raportează corect numărul de aplicații")
        _assert(data['top_apps'][0]['app_name'] == '🎵 TikTok', "Top aplicații este ordonat după bytes_total")
        _assert(round(data['top_apps'][0]['traffic_percent'], 2) == 70.00, "Procentajul traficului este calculat corect")

        filtered = client.get('/api/statistics/app-usage?period=today&app=tiktok').get_json()
        _assert(len(filtered['top_apps']) == 1, "Filtrarea după aplicație/hostname funcționează")
        _assert(filtered['top_apps'][0]['app_name'] == '🎵 TikTok', "Filtrarea returnează aplicația cerută")
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_api_app_usage_handles_missing_hostnames_and_timeline_order():
    print("\n--- /api/statistics/app-usage (hostname null + timeline) ---")

    app, db_path = _build_app()
    try:
        from app import db
        from app.models import User, AppTrafficStat

        with app.app_context():
            admin = User.query.filter_by(username='admin-test').first()
            db.session.add_all([
                AppTrafficStat(
                    stat_date=datetime(2025, 12, 31, tzinfo=timezone.utc).date(),
                    source_ip='192.168.224.8',
                    hostname='unknown.local',
                    app_name=None,
                    bytes_total=1000,
                    packets_count=10,
                    first_seen=datetime(2025, 12, 31, 12, 0, tzinfo=timezone.utc),
                    last_seen=datetime(2025, 12, 31, 12, 10, tzinfo=timezone.utc),
                ),
                AppTrafficStat(
                    stat_date=datetime(2026, 1, 1, tzinfo=timezone.utc).date(),
                    source_ip='192.168.224.9',
                    hostname='example.org',
                    app_name='Example',
                    bytes_total=2000,
                    packets_count=20,
                    first_seen=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
                    last_seen=datetime(2026, 1, 1, 12, 10, tzinfo=timezone.utc),
                ),
            ])
            db.session.commit()
            admin_id = admin.id

        client = app.test_client()
        _login(client, admin_id)
        response = client.get('/api/statistics/app-usage?period=all')
        data = response.get_json()

        _assert(response.status_code == 200, "API-ul app-usage răspunde cu 200 când există hostname-uri lipsă")
        _assert(data['timeline']['labels'] == ['31.12', '01.01'], "Timeline-ul este ordonat cronologic pe date reale")
        fallback_apps = [app for app in data['top_apps'] if app['app_name'] == 'unknown.local']
        _assert(bool(fallback_apps), "Intrările fără app_name folosesc fallback-ul pe hostname")
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_network_bulk_update_and_export_csv():
    print("\n--- /api/network/devices/bulk-update + /network/export.csv ---")

    app, db_path = _build_app()
    try:
        from app import db
        from app.models import User, NetworkDevice

        with app.app_context():
            admin = User.query.filter_by(username='admin-test').first()
            d1 = NetworkDevice(ip_address='192.168.224.21', device_type='unknown', is_known=False)
            d2 = NetworkDevice(ip_address='192.168.224.22', device_type='unknown', is_known=False)
            db.session.add_all([d1, d2])
            db.session.commit()
            admin_id = admin.id
            d1_id = d1.id
            d2_id = d2.id

        client = app.test_client()
        _login(client, admin_id)
        bulk_response = client.post('/api/network/devices/bulk-update', json={
            'action': 'mark_known',
            'device_ids': [d1_id, d2_id],
        })
        bulk_data = bulk_response.get_json()
        _assert(bulk_response.status_code == 200, "Bulk update endpoint răspunde cu 200")
        _assert(bulk_data.get('updated') == 2, "Bulk update actualizează numărul corect de dispozitive")

        with app.app_context():
            devices = NetworkDevice.query.filter(NetworkDevice.id.in_([d1_id, d2_id])).all()
            _assert(all(d.is_known for d in devices), "Bulk update setează is_known=True pentru dispozitivele selectate")

        export_resp = client.get('/network/export.csv')
        _assert(export_resp.status_code == 200, "Export CSV pentru network răspunde cu 200")
        _assert('text/csv' in (export_resp.content_type or ''), "Export CSV pentru network returnează mimetype corect")
        body = export_resp.get_data(as_text=True)
        _assert('192.168.224.21' in body and '192.168.224.22' in body, "CSV-ul exportat conține dispozitivele așteptate")
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_statistics_app_usage_export_csv():
    print("\n--- /statistics/apps/export.csv ---")

    app, db_path = _build_app()
    try:
        from app import db
        from app.models import User, AppTrafficStat

        now = datetime.now(timezone.utc)
        with app.app_context():
            admin = User.query.filter_by(username='admin-test').first()
            db.session.add(AppTrafficStat(
                stat_date=now.date(),
                source_ip='192.168.224.33',
                hostname='youtube.com',
                app_name='▶️ YouTube',
                bytes_total=12345,
                packets_count=99,
                first_seen=now - timedelta(minutes=5),
                last_seen=now,
            ))
            db.session.commit()
            admin_id = admin.id

        client = app.test_client()
        _login(client, admin_id)
        resp = client.get('/statistics/apps/export.csv?period=today&app=youtube')
        _assert(resp.status_code == 200, "Export CSV app-usage răspunde cu 200")
        _assert('text/csv' in (resp.content_type or ''), "Export CSV app-usage returnează mimetype corect")
        csv_body = resp.get_data(as_text=True)
        _assert('youtube.com' in csv_body, "CSV app-usage conține datele filtrate")
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


if __name__ == '__main__':
    test_api_ip_connections_returns_sorted_results()
    test_update_device_can_remove_known_flag_without_typeerror()
    test_reclassify_mobile_includes_unknown_devices()
    test_cleanup_old_ip_connections_respects_retention()
    test_api_app_usage_returns_percentages_and_filters()
    test_api_app_usage_handles_missing_hostnames_and_timeline_order()
    test_network_bulk_update_and_export_csv()
    test_statistics_app_usage_export_csv()

    print(f"\n{'='*40}")
    print(f"Rezultat: {_pass_count} PASS, {_fail_count} FAIL")
    if _fail_count:
        print("EȘEC: unele teste au picat.")
        sys.exit(1)
    else:
        print("SUCCES: toate testele au trecut.")
        sys.exit(0)
