"""
Blueprint Flask pentru API-ul de integrare MikroTik RouterOS.
Expune rute pentru starea conexiunii, DHCP leases, conexiuni active,
statistici interfețe și blocarea/deblocarea IP-urilor pe router.
"""
from flask import Blueprint, jsonify, current_app
from flask_login import login_required, current_user

mikrotik_bp = Blueprint('mikrotik', __name__)


def _get_mikrotik():
    """Returnează instanța MikrotikClient atașată aplicației (sau None)."""
    return getattr(current_app, 'mikrotik_client', None)


# ------------------------------------------------------------------
# GET /api/mikrotik/status
# ------------------------------------------------------------------

@mikrotik_bp.route('/api/mikrotik/status')
@login_required
def status():
    """Starea conexiunii cu routerul MikroTik."""
    mikrotik = _get_mikrotik()
    enabled = current_app.config.get('MIKROTIK_ENABLED', False)

    connected = mikrotik is not None and mikrotik.is_connected()
    identity = ''
    if connected:
        identity = mikrotik.get_router_identity()

    return jsonify({
        'connected': connected,
        'router_identity': identity,
        'enabled': enabled,
    })


# ------------------------------------------------------------------
# GET /api/mikrotik/dhcp-leases
# ------------------------------------------------------------------

@mikrotik_bp.route('/api/mikrotik/dhcp-leases')
@login_required
def dhcp_leases():
    """Lista sesiunilor DHCP active de pe router."""
    mikrotik = _get_mikrotik()
    if mikrotik is None or not mikrotik.is_connected():
        return jsonify([])
    return jsonify(mikrotik.get_dhcp_leases())


# ------------------------------------------------------------------
# GET /api/mikrotik/connections
# ------------------------------------------------------------------

@mikrotik_bp.route('/api/mikrotik/connections')
@login_required
def active_connections():
    """Conexiunile active din firewall-ul routerului (maxim 100)."""
    mikrotik = _get_mikrotik()
    if mikrotik is None or not mikrotik.is_connected():
        return jsonify([])
    return jsonify(mikrotik.get_active_connections()[:100])


# ------------------------------------------------------------------
# GET /api/mikrotik/interfaces
# ------------------------------------------------------------------

@mikrotik_bp.route('/api/mikrotik/interfaces')
@login_required
def interfaces():
    """Statistici trafic per interfață."""
    mikrotik = _get_mikrotik()
    if mikrotik is None or not mikrotik.is_connected():
        return jsonify([])
    return jsonify(mikrotik.get_interface_traffic())


# ------------------------------------------------------------------
# POST /api/mikrotik/block/<ip>
# ------------------------------------------------------------------

@mikrotik_bp.route('/api/mikrotik/block/<ip>', methods=['POST'])
@login_required
def block_ip(ip):
    """Blochează IP-ul pe router (doar admin)."""
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Acces interzis.'}), 403

    mikrotik = _get_mikrotik()
    if mikrotik is None or not mikrotik.is_connected():
        return jsonify({'success': False, 'message': 'Routerul MikroTik nu este conectat.'}), 503

    success = mikrotik.block_ip_on_router(
        ip,
        comment=f'Blocat din SchoolSec de {current_user.username}',
    )
    if success:
        return jsonify({'success': True, 'message': f'IP {ip} blocat pe router.'})
    return jsonify({'success': False, 'message': f'Eroare la blocarea IP-ului {ip}.'}), 500


# ------------------------------------------------------------------
# POST /api/mikrotik/unblock/<ip>
# ------------------------------------------------------------------

@mikrotik_bp.route('/api/mikrotik/unblock/<ip>', methods=['POST'])
@login_required
def unblock_ip(ip):
    """Deblochează IP-ul de pe router (doar admin)."""
    if not current_user.is_admin():
        return jsonify({'success': False, 'message': 'Acces interzis.'}), 403

    mikrotik = _get_mikrotik()
    if mikrotik is None or not mikrotik.is_connected():
        return jsonify({'success': False, 'message': 'Routerul MikroTik nu este conectat.'}), 503

    success = mikrotik.unblock_ip_on_router(ip)
    if success:
        return jsonify({'success': True, 'message': f'IP {ip} deblocat pe router.'})
    return jsonify({'success': False, 'message': f'Eroare la deblocarea IP-ului {ip}.'}), 500
