"""
Rutele pentru pagina de statistici istorice.
"""
from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required
from sqlalchemy import func, or_
from app.models import Alert, AppTrafficStat
from app import db

statistics_bp = Blueprint('statistics', __name__)


def _get_period_start(period):
    """Returnează timestamp-ul de start pentru perioada dată."""
    now = datetime.now(timezone.utc)
    if period == '24h':
        return now - timedelta(hours=24)
    elif period == '7d':
        return now - timedelta(days=7)
    elif period == '30d':
        return now - timedelta(days=30)
    else:
        return None  # 'all' — fără filtru de timp


def _get_app_period_start(period):
    """Returnează începutul perioadei pentru statisticile pe aplicații."""
    now = datetime.now(timezone.utc)
    if period == 'today':
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == '7d':
        return now - timedelta(days=7)
    if period == '30d':
        return now - timedelta(days=30)
    return None


def _build_timeline(alerts, period):
    """Construiește datele pentru graficul de tip linie (timeline)."""
    now = datetime.now(timezone.utc)
    severities = ['critical', 'high', 'medium', 'low']

    if period == '24h':
        # Grupăm pe ore (ultimele 24h)
        labels = []
        buckets = {}
        for i in range(23, -1, -1):
            dt = now - timedelta(hours=i)
            label = dt.strftime('%H:00')
            labels.append(label)
            buckets[label] = {s: 0 for s in severities}

        for alert in alerts:
            ts = alert.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            label = ts.strftime('%H:00')
            if label in buckets:
                buckets[label][alert.severity] = buckets[label].get(alert.severity, 0) + 1

    elif period in ('7d', '30d'):
        # Grupăm pe zile
        days = 7 if period == '7d' else 30
        labels = []
        buckets = {}
        for i in range(days - 1, -1, -1):
            dt = now - timedelta(days=i)
            label = dt.strftime('%d.%m')
            labels.append(label)
            buckets[label] = {s: 0 for s in severities}

        for alert in alerts:
            ts = alert.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            label = ts.strftime('%d.%m')
            if label in buckets:
                buckets[label][alert.severity] = buckets[label].get(alert.severity, 0) + 1

    else:
        # 'all' — grupăm pe zile (ultimele 30 de zile cu date)
        if not alerts:
            return {'labels': [], 'critical': [], 'high': [], 'medium': [], 'low': []}

        # Găsim intervalul cu date
        timestamps = [
            a.timestamp if a.timestamp.tzinfo else a.timestamp.replace(tzinfo=timezone.utc)
            for a in alerts
        ]
        min_dt = min(timestamps)
        max_dt = max(timestamps)
        delta = (max_dt - min_dt).days + 1
        labels = []
        buckets = {}
        for i in range(delta):
            dt = min_dt + timedelta(days=i)
            label = dt.strftime('%d.%m')
            labels.append(label)
            buckets[label] = {s: 0 for s in severities}

        for alert in alerts:
            ts = alert.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            label = ts.strftime('%d.%m')
            if label in buckets:
                buckets[label][alert.severity] = buckets[label].get(alert.severity, 0) + 1

    return {
        'labels': labels,
        'critical': [buckets[l]['critical'] for l in labels],
        'high': [buckets[l]['high'] for l in labels],
        'medium': [buckets[l]['medium'] for l in labels],
        'low': [buckets[l]['low'] for l in labels],
    }


@statistics_bp.route('/statistics')
@login_required
def index():
    """Pagina de statistici istorice."""
    period = request.args.get('period', '24h')
    if period not in ('24h', '7d', '30d', 'all'):
        period = '24h'
    return render_template('statistics.html', period=period)


@statistics_bp.route('/statistics/apps')
@login_required
def app_usage():
    """Pagina de analytics pentru aplicațiile/site-urile accesate."""
    period = request.args.get('period', 'today')
    if period not in ('today', '7d', '30d', 'all'):
        period = 'today'
    return render_template('app_usage.html', period=period)


@statistics_bp.route('/api/statistics')
@login_required
def api_statistics():
    """API endpoint pentru datele statisticilor istorice."""
    period = request.args.get('period', '24h')
    if period not in ('24h', '7d', '30d', 'all'):
        period = '24h'

    period_start = _get_period_start(period)

    # Query de bază
    query = Alert.query
    if period_start is not None:
        query = query.filter(Alert.timestamp >= period_start)

    alerts = query.all()

    # --- Summary ---
    total = len(alerts)
    critical = sum(1 for a in alerts if a.severity == 'critical')
    high = sum(1 for a in alerts if a.severity == 'high')
    medium = sum(1 for a in alerts if a.severity == 'medium')
    low = sum(1 for a in alerts if a.severity == 'low')
    unique_ips = len({a.source_ip for a in alerts})
    resolved = sum(1 for a in alerts if a.status == 'resolved')
    resolved_pct = round(resolved / total * 100, 1) if total > 0 else 0.0

    summary = {
        'total': total,
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'unique_ips': unique_ips,
        'resolved_percentage': resolved_pct,
    }

    # --- Timeline ---
    timeline = _build_timeline(alerts, period)

    # --- Top 10 IP-uri sursă ---
    ip_counts = {}
    ip_last_seen = {}
    for a in alerts:
        ip_counts[a.source_ip] = ip_counts.get(a.source_ip, 0) + 1
        ts = a.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if a.source_ip not in ip_last_seen or ts > ip_last_seen[a.source_ip]:
            ip_last_seen[a.source_ip] = ts

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_ips_data = [
        {
            'ip': ip,
            'count': count,
            'last_seen': ip_last_seen[ip].strftime('%d.%m %H:%M'),
        }
        for ip, count in top_ips
    ]

    # --- By type ---
    by_type = {}
    for a in alerts:
        by_type[a.alert_type] = by_type.get(a.alert_type, 0) + 1

    # --- By severity ---
    by_severity = {
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
    }

    # --- Top 10 alerte critice/high recente ---
    recent_critical = (
        Alert.query
        .filter(Alert.severity.in_(['critical', 'high']))
        .order_by(Alert.timestamp.desc())
        .limit(10)
        .all()
    )
    recent_critical_data = [
        {
            'id': a.id,
            'alert_type': a.alert_type,
            'source_ip': a.source_ip,
            'severity': a.severity,
            'status': a.status,
            'message': a.message,
            'timestamp': a.timestamp.strftime('%d.%m.%Y %H:%M'),
        }
        for a in recent_critical
    ]

    return jsonify({
        'period': period,
        'summary': summary,
        'timeline': timeline,
        'top_ips': top_ips_data,
        'by_type': by_type,
        'by_severity': by_severity,
        'recent_critical': recent_critical_data,
    })


@statistics_bp.route('/api/statistics/app-usage')
@login_required
def api_app_usage():
    """Returnează analytics agregat pentru aplicații/site-uri accesate."""
    period = request.args.get('period', 'today')
    if period not in ('today', '7d', '30d', 'all'):
        period = 'today'
    search = (request.args.get('app') or '').strip().lower()

    period_start = _get_app_period_start(period)
    query = AppTrafficStat.query
    if period_start is not None:
        query = query.filter(AppTrafficStat.last_seen >= period_start)
    if search:
        like_value = f'%{search}%'
        query = query.filter(
            or_(
                AppTrafficStat.app_name.ilike(like_value),
                AppTrafficStat.hostname.ilike(like_value),
            )
        )

    rows = query.all()

    app_totals = {}
    timeline_buckets = {}
    total_bytes = 0
    total_packets = 0
    unique_ips = set()
    latest_seen = None

    for row in rows:
        key = (row.app_name or row.hostname or 'Necunoscut').strip() or 'Necunoscut'
        entry = app_totals.setdefault(key, {
            'app_name': key,
            'bytes_total': 0,
            'packets_count': 0,
            'unique_ips': set(),
            'last_seen': None,
            'hostnames': set(),
        })
        entry['bytes_total'] += row.bytes_total or 0
        entry['packets_count'] += row.packets_count or 0
        entry['unique_ips'].add(row.source_ip)
        entry['hostnames'].add(row.hostname)
        if entry['last_seen'] is None or (row.last_seen and row.last_seen > entry['last_seen']):
            entry['last_seen'] = row.last_seen

        total_bytes += row.bytes_total or 0
        total_packets += row.packets_count or 0
        unique_ips.add(row.source_ip)
        if latest_seen is None or (row.last_seen and row.last_seen > latest_seen):
            latest_seen = row.last_seen

        label = row.stat_date.strftime('%d.%m')
        bucket = timeline_buckets.setdefault(label, 0)
        timeline_buckets[label] = bucket + (row.bytes_total or 0)

    apps = []
    for entry in app_totals.values():
        pct = round((entry['bytes_total'] / total_bytes) * 100, 2) if total_bytes > 0 else 0.0
        apps.append({
            'app_name': entry['app_name'],
            'bytes_total': entry['bytes_total'],
            'packets_count': entry['packets_count'],
            'unique_ips': len(entry['unique_ips']),
            'traffic_percent': pct,
            'last_seen': entry['last_seen'].strftime('%d.%m.%Y %H:%M:%S') if entry['last_seen'] else 'N/A',
            'top_hostnames': sorted(entry['hostnames'])[:3],
        })

    apps.sort(key=lambda item: item['bytes_total'], reverse=True)
    top_apps = apps[:15]

    timeline_labels = sorted(
        timeline_buckets.keys(),
        key=lambda label: datetime.strptime(label, '%d.%m')
    ) if timeline_buckets else []
    timeline = {
        'labels': timeline_labels,
        'bytes_total': [timeline_buckets[label] for label in timeline_labels],
    }

    return jsonify({
        'period': period,
        'summary': {
            'total_apps': len(apps),
            'total_bytes': total_bytes,
            'total_packets': total_packets,
            'unique_ips': len(unique_ips),
            'latest_seen': latest_seen.strftime('%d.%m.%Y %H:%M:%S') if latest_seen else 'N/A',
        },
        'top_apps': top_apps,
        'timeline': timeline,
    })
