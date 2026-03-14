"""
Blueprint Flask pentru pagina de Securitate Externă.
Expune pagina dedicată și API-urile pentru log-urile firewall, tentativele
de login pe router, starea resurselor și statistici atacuri externe.
"""
from datetime import datetime, timedelta, timezone

from flask import Blueprint, render_template, jsonify, current_app
from flask_login import login_required

from app import db
from app.models import Alert

external_bp = Blueprint('external', __name__)


def _get_mikrotik():
    """Returnează instanța MikrotikClient atașată aplicației (sau None)."""
    return getattr(current_app, 'mikrotik_client', None)


# ------------------------------------------------------------------
# GET /external-security
# ------------------------------------------------------------------

@external_bp.route('/external-security')
@login_required
def index():
    """Pagina de securitate externă."""
    mikrotik = _get_mikrotik()
    connected = mikrotik is not None and mikrotik.is_connected()

    # Statistici atacuri externe din ultimele 24h
    since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    external_attacks_24h = Alert.query.filter(
        Alert.alert_type.like('external_%'),
        Alert.timestamp >= since_24h,
    ).count()

    # Tentative login (contorizare din log)
    login_attempts = []
    login_failures_count = 0
    firewall_logs = []
    router_health = {}
    blocked_list = []
    firewall_rules = {}

    if connected:
        try:
            firewall_logs = mikrotik.get_firewall_log(limit=50)
        except Exception as e:
            print(f"[external.index] Eroare get_firewall_log: {e}")

        try:
            login_attempts = mikrotik.get_login_attempts(limit=20)
            login_failures_count = sum(1 for a in login_attempts if not a.get('success'))
        except Exception as e:
            print(f"[external.index] Eroare get_login_attempts: {e}")

        try:
            router_health = mikrotik.get_system_resources()
        except Exception as e:
            print(f"[external.index] Eroare get_system_resources: {e}")

        try:
            blocked_list = mikrotik.get_address_list_entries('schoolsec-blocked')
        except Exception as e:
            print(f"[external.index] Eroare get_address_list_entries: {e}")

        try:
            firewall_rules = mikrotik.get_firewall_rules_count()
        except Exception as e:
            print(f"[external.index] Eroare get_firewall_rules_count: {e}")

    # CPU și RAM pentru carduri
    cpu_load = router_health.get('cpu_load', 0)
    free_mem = router_health.get('free_memory', 0)
    total_mem = router_health.get('total_memory', 1)
    ram_free_pct = round(free_mem / total_mem * 100, 1) if total_mem else 0

    # Alerte externe din DB (ultimele 20 cu prefix external_ sau router_)
    from sqlalchemy import or_
    recent_external_alerts = Alert.query.filter(
        or_(
            Alert.alert_type.like('external_%'),
            Alert.alert_type.like('router_%'),
        )
    ).order_by(Alert.timestamp.desc()).limit(20).all()

    return render_template(
        'external_security.html',
        connected=connected,
        external_attacks_24h=external_attacks_24h,
        login_failures_count=login_failures_count,
        cpu_load=cpu_load,
        ram_free_pct=ram_free_pct,
        router_health=router_health,
        firewall_logs=firewall_logs,
        login_attempts=login_attempts,
        blocked_list=blocked_list,
        firewall_rules=firewall_rules,
        recent_external_alerts=recent_external_alerts,
    )


# ------------------------------------------------------------------
# GET /api/external/firewall-log
# ------------------------------------------------------------------

@external_bp.route('/api/external/firewall-log')
@login_required
def firewall_log():
    """API: ultimele log-uri firewall."""
    mikrotik = _get_mikrotik()
    if mikrotik is None or not mikrotik.is_connected():
        return jsonify([])
    try:
        return jsonify(mikrotik.get_firewall_log(limit=50))
    except Exception as e:
        print(f"[external.firewall_log] Eroare: {e}")
        return jsonify([])


# ------------------------------------------------------------------
# GET /api/external/login-attempts
# ------------------------------------------------------------------

@external_bp.route('/api/external/login-attempts')
@login_required
def login_attempts():
    """API: tentative de login pe router."""
    mikrotik = _get_mikrotik()
    if mikrotik is None or not mikrotik.is_connected():
        return jsonify([])
    try:
        return jsonify(mikrotik.get_login_attempts(limit=20))
    except Exception as e:
        print(f"[external.login_attempts] Eroare: {e}")
        return jsonify([])


# ------------------------------------------------------------------
# GET /api/external/router-health
# ------------------------------------------------------------------

@external_bp.route('/api/external/router-health')
@login_required
def router_health():
    """API: starea resurselor routerului."""
    mikrotik = _get_mikrotik()
    if mikrotik is None or not mikrotik.is_connected():
        return jsonify({})
    try:
        return jsonify(mikrotik.get_system_resources())
    except Exception as e:
        print(f"[external.router_health] Eroare: {e}")
        return jsonify({})


# ------------------------------------------------------------------
# GET /api/external/stats
# ------------------------------------------------------------------

@external_bp.route('/api/external/stats')
@login_required
def external_stats():
    """API: statistici atacuri externe (pentru AJAX refresh)."""
    mikrotik = _get_mikrotik()
    connected = mikrotik is not None and mikrotik.is_connected()

    since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    external_attacks_24h = Alert.query.filter(
        Alert.alert_type.like('external_%'),
        Alert.timestamp >= since_24h,
    ).count()

    login_failures_count = 0
    cpu_load = 0
    ram_free_pct = 0

    if connected:
        try:
            attempts = mikrotik.get_login_attempts(limit=50)
            login_failures_count = sum(1 for a in attempts if not a.get('success'))
        except Exception:
            pass

        try:
            resources = mikrotik.get_system_resources()
            cpu_load = resources.get('cpu_load', 0)
            free_mem = resources.get('free_memory', 0)
            total_mem = resources.get('total_memory', 1)
            ram_free_pct = round(free_mem / total_mem * 100, 1) if total_mem else 0
        except Exception:
            pass

    return jsonify({
        'connected': connected,
        'external_attacks_24h': external_attacks_24h,
        'login_failures_count': login_failures_count,
        'cpu_load': cpu_load,
        'ram_free_pct': ram_free_pct,
    })
