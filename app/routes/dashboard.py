"""
Rutele pentru dashboard-ul principal.
"""
import csv
import io
from datetime import datetime, timezone
from flask import Blueprint, render_template, jsonify, request, Response
from flask_login import login_required
from app.models import Alert, SecurityLog, BlockedIP, BlockedHostname, NetworkDevice
from app.ids.sniffer import get_stats
from app import db

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@login_required
def index():
    """Pagina principală cu statistici."""
    # Numărul total de alerte active
    active_alerts = Alert.query.filter_by(status='active').count()
    # Numărul de IP-uri blocate
    blocked_ips_count = BlockedIP.query.filter_by(is_active=True).count()
    # Numărul de hostname-uri blocate
    blocked_hostnames_count = BlockedHostname.query.filter_by(is_active=True).count()
    # Ultimele 5 alerte
    recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(5).all()
    # Statistici trafic
    stats = get_stats()
    top_sources_bytes = (
        NetworkDevice.query
        .filter(NetworkDevice.total_bytes > 0)
        .order_by(NetworkDevice.total_bytes.desc())
        .limit(10)
        .all()
    )

    return render_template(
        'dashboard.html',
        active_alerts=active_alerts,
        blocked_ips_count=blocked_ips_count,
        blocked_hostnames_count=blocked_hostnames_count,
        recent_alerts=recent_alerts,
        stats=stats,
        top_sources_bytes=top_sources_bytes,
    )


@dashboard_bp.route('/api/stats')
@login_required
def api_stats():
    """API endpoint pentru statistici live (AJAX)."""
    stats = get_stats()
    active_alerts = Alert.query.filter_by(status='active').count()
    blocked_ips = BlockedIP.query.filter_by(is_active=True).count()
    blocked_hostnames = BlockedHostname.query.filter_by(is_active=True).count()

    return jsonify({
        'total_packets': stats['total_packets'],
        'bytes_total': stats['bytes_total'],
        'active_alerts': active_alerts,
        'blocked_ips': blocked_ips,
        'blocked_hostnames': blocked_hostnames,
        'protocols': stats['protocols'],
        'top_sources': stats['top_sources'],
        'last_packets': stats['last_packets'],
    })


@dashboard_bp.route('/logs')
@login_required
def logs():
    """Pagina cu logurile de securitate, filtrabilă."""
    # Parametrii de filtrare
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity', '')
    event_type = request.args.get('event_type', '')
    search = request.args.get('search', '')

    # Construim query-ul
    query = SecurityLog.query

    if severity:
        query = query.filter_by(severity=severity)
    if event_type:
        query = query.filter_by(event_type=event_type)
    if search:
        query = query.filter(
            (SecurityLog.source_ip.contains(search)) |
            (SecurityLog.message.contains(search))
        )

    # Paginare
    logs_paginated = query.order_by(SecurityLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )

    # Tipurile de evenimente unice pentru filtrul dropdown
    event_types = db.session.query(SecurityLog.event_type).distinct().all()
    event_types = [e[0] for e in event_types]

    return render_template(
        'logs.html',
        logs=logs_paginated,
        severity=severity,
        event_type=event_type,
        search=search,
        event_types=event_types
    )


@dashboard_bp.route('/logs/export')
@login_required
def export_logs():
    """Exportă logurile în format CSV."""
    severity = request.args.get('severity', '')
    event_type = request.args.get('event_type', '')

    query = SecurityLog.query
    if severity:
        query = query.filter_by(severity=severity)
    if event_type:
        query = query.filter_by(event_type=event_type)

    logs = query.order_by(SecurityLog.timestamp.desc()).all()

    # Creăm fișierul CSV în memorie
    output = io.StringIO()
    writer = csv.writer(output)

    # Header CSV
    writer.writerow(['ID', 'Timestamp', 'Tip Eveniment', 'IP Sursă',
                     'IP Destinație', 'Protocol', 'Port', 'Severitate', 'Mesaj'])

    # Date CSV
    for log in logs:
        writer.writerow([
            log.id,
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.event_type,
            log.source_ip or '',
            log.destination_ip or '',
            log.protocol or '',
            log.port or '',
            log.severity,
            log.message
        ])

    output.seek(0)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename=security_logs_{timestamp}.csv'
        }
    )
