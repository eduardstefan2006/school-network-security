"""
Rute pentru pagina Hartă Rețea.
Afișează toate dispozitivele detectate în rețea.
"""
from datetime import datetime
from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user

from app import db
from app.models import NetworkDevice, Alert


network_bp = Blueprint('network', __name__)


@network_bp.route('/api/network/ip/<string:ip_address>/connections')
@login_required
def api_ip_connections(ip_address):
    """Returnează site-urile/aplicațiile accesate de un IP, ordonate după bytes."""
    from app.models import IPConnection
    connections = (
        IPConnection.query
        .filter_by(source_ip=ip_address)
        .order_by(IPConnection.bytes_total.desc())
        .limit(50)
        .all()
    )
    return jsonify([{
        'hostname': c.hostname,
        'app_name': c.app_name or c.hostname,
        'bytes_total': c.bytes_total,
        'packets_count': c.packets_count,
        'last_seen': c.last_seen.strftime('%d.%m.%Y %H:%M:%S') if c.last_seen else 'N/A',
    } for c in connections])


@network_bp.route('/network')
@login_required
def index():
    """Pagina hartă rețea cu toate dispozitivele detectate."""
    devices = NetworkDevice.query.order_by(NetworkDevice.last_seen.desc()).all()
    now = datetime.utcnow()
    for device in devices:
        device.is_online = (now - device.last_seen).total_seconds() < 300

    # Statistici sumare pentru carduri
    total = len(devices)
    online = sum(1 for d in devices if d.is_online)
    unknown = sum(1 for d in devices if not d.is_known)

    # Statistici pe tip de dispozitiv
    type_counts = {}
    for d in devices:
        type_counts[d.device_type] = type_counts.get(d.device_type, 0) + 1

    return render_template(
        'network.html',
        devices=devices,
        total=total,
        online=online,
        unknown=unknown,
        type_counts=type_counts,
    )


@network_bp.route('/api/network/devices')
@login_required
def api_devices():
    """API endpoint returnând toate dispozitivele ca JSON."""
    devices = NetworkDevice.query.order_by(NetworkDevice.last_seen.desc()).all()
    now = datetime.utcnow()
    return jsonify([{
        'id': d.id,
        'ip': d.ip_address,
        'mac': d.mac_address or 'N/A',
        'hostname': d.hostname or '-',
        'type': d.device_type,
        'description': d.description or '-',
        'first_seen': d.first_seen.strftime('%d.%m.%Y %H:%M'),
        'last_seen': d.last_seen.strftime('%d.%m.%Y %H:%M'),
        'packets': d.total_packets,
        'is_known': d.is_known,
        'is_online': (now - d.last_seen).total_seconds() < 300,
        'alert_count': d.alert_count,
        'vlan': d.vlan or '-',
    } for d in devices])


@network_bp.route('/api/network/device/<int:device_id>/update', methods=['POST'])
@login_required
def update_device(device_id):
    """Admin: actualizează descrierea și tipul unui dispozitiv."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis'}), 403
    device = db.session.get(NetworkDevice, device_id)
    # Fallback: caută după IP dacă ID-ul nu mai există (dispozitiv recreat după reset)
    if device is None:
        data = request.get_json(silent=True) or {}
        ip = data.get('ip')
        if ip:
            device = NetworkDevice.query.filter_by(ip_address=ip).first()
    if device is None:
        return jsonify({'error': 'Dispozitiv negăsit'}), 404
    data = request.get_json(silent=True) or {}
    if 'description' in data:
        device.description = data['description']
    if 'device_type' in data:
        device.device_type = data['device_type']
    if 'type_locked' in data:
        device.type_locked = bool(data['type_locked'])
    if 'is_known' in data:
        device.is_known = bool(data['is_known'])
        # Actualizăm tipul dispozitivului în funcție de flagul is_known
        if device.is_known and not device.type_locked:
            device.device_type = 'known'
        elif not device.is_known and device.device_type == 'known' and not device.type_locked:
            # Când se elimină flagul "Cunoscut", reclasificăm dispozitivul
            from app.ids.sniffer import _detect_device_type, _calc_online_hours
            vlan_id = None
            if device.vlan:
                try:
                    vlan_id = int(device.vlan)
                except (ValueError, TypeError):
                    pass
            device.device_type = _detect_device_type(
                device.ip_address,
                mac=device.mac_address,
                vlan_id=vlan_id,
                hostname=device.hostname,
                online_hours=_calc_online_hours(device),
                is_known=False,
            )
        # Auto-rezolvă alertele new_device active când dispozitivul devine cunoscut
        if device.is_known and device.ip_address:
            Alert.query.filter_by(
                alert_type='new_device',
                source_ip=device.ip_address,
                status='active',
            ).update({'status': 'resolved'}, synchronize_session=False)
        # Invalidăm cache-ul de whitelist pentru a include/exclude noul dispozitiv
        try:
            from app.ids.detector import invalidate_whitelist_cache
            invalidate_whitelist_cache()
        except Exception:
            pass
    db.session.commit()
    return jsonify({'success': True})


@network_bp.route('/api/network/reclassify-devices', methods=['POST'])
@login_required
def reclassify_devices():
    """Admin: reclasifică manual toate dispozitivele din DB."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis'}), 403
    try:
        from app.ids.sniffer import _fix_device_types, _fix_device_vlans
        from flask import current_app
        _fix_device_types(current_app._get_current_object())
        _fix_device_vlans(current_app._get_current_object())
        return jsonify({'success': True, 'message': 'Dispozitivele au fost reclasificate.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@network_bp.route('/api/devices/reclassify-mobile', methods=['POST'])
@login_required
def reclassify_mobile_devices():
    """Reclasifică dispozitivele 'client' sau 'unknown' care ar trebui să fie 'mobile'."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis'}), 403
    from app.ids.sniffer import _detect_device_type, _mobile_traffic_hints, _calc_online_hours
    from app.models import NetworkDevice

    reclassified = []
    devices = NetworkDevice.query.filter(
        NetworkDevice.device_type.in_(('client', 'unknown'))
    ).all()
    for device in devices:
        # Skip devices with locked type or known infrastructure
        if device.type_locked or device.is_known:
            continue
        vlan_id = None
        if device.vlan:
            try:
                vlan_id = int(device.vlan)
            except (ValueError, TypeError):
                pass
        new_type = _detect_device_type(device.ip_address, mac=device.mac_address, vlan_id=vlan_id, hostname=device.hostname, online_hours=_calc_online_hours(device))
        if new_type == 'mobile':
            device.device_type = 'mobile'
            reclassified.append(device.ip_address)

    if reclassified:
        db.session.commit()

    return jsonify({
        'reclassified': len(reclassified),
        'ips': reclassified
    })


@network_bp.route('/api/devices/deduplicate', methods=['POST'])
@login_required
def deduplicate_devices():
    """Admin: deduplicare dispozitive cu același MAC și IP-uri diferite."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis'}), 403
    try:
        from app.ids.sniffer import _deduplicate_devices
        from flask import current_app
        deleted = _deduplicate_devices(current_app._get_current_object())
        return jsonify({'success': True, 'deleted': deleted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@network_bp.route('/api/devices/cleanup-inactive', methods=['POST'])
@login_required
def cleanup_inactive_devices():
    """Șterge manual dispozitivele mobile inactive cu MAC randomizat."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis'}), 403
    try:
        from app.ids.sniffer import _cleanup_inactive_mobile_devices
        from flask import current_app
        ttl_hours = request.json.get('ttl_hours', 24) if request.is_json else 24
        deleted = _cleanup_inactive_mobile_devices(current_app._get_current_object(), ttl_hours=ttl_hours)
        return jsonify({
            'success': True,
            'deleted': deleted,
            'message': f'{deleted} dispozitive inactive șterse.'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@network_bp.route('/api/devices/deduplicate-mobile', methods=['POST'])
@login_required
def deduplicate_mobile_devices():
    """Admin: deduplicare dispozitive mobile cu același MAC (inclusiv MAC randomizat)."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis'}), 403
    try:
        from app.ids.sniffer import _deduplicate_all_mobile_devices
        from flask import current_app
        deleted = _deduplicate_all_mobile_devices(current_app._get_current_object())
        return jsonify({'success': True, 'deleted': deleted, 'message': f'{deleted} duplicate eliminate.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
