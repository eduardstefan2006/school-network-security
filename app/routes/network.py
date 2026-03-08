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
    new_device_alerts = Alert.query.filter_by(alert_type='new_device', status='active').count()

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
        new_device_alerts=new_device_alerts,
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
    if device is None:
        return jsonify({'error': 'Dispozitiv negăsit'}), 404
    data = request.get_json(silent=True) or {}
    if 'description' in data:
        device.description = data['description']
    if 'device_type' in data:
        device.device_type = data['device_type']
    if 'is_known' in data:
        device.is_known = bool(data['is_known'])
    db.session.commit()
    return jsonify({'success': True})
