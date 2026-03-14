"""
Rutele pentru gestionarea alertelor de securitate.
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user
from app.models import Alert, BlockedIP, BlockedMAC, NetworkDevice, SecurityLog
from app import db

alerts_bp = Blueprint('alerts', __name__)


@alerts_bp.route('/alerts')
@login_required
def index():
    """Pagina cu lista de alerte."""
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', '')
    severity = request.args.get('severity', '')
    alert_type = request.args.get('type', '')

    query = Alert.query

    if status:
        query = query.filter_by(status=status)
    if severity:
        query = query.filter_by(severity=severity)
    if alert_type:
        query = query.filter_by(alert_type=alert_type)

    alerts = query.order_by(Alert.timestamp.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    # Statistici pentru badge-uri
    stats = {
        'active': Alert.query.filter_by(status='active').count(),
        'critical': Alert.query.filter_by(severity='critical').count(),
        'high': Alert.query.filter_by(severity='high').count(),
    }

    return render_template('alerts.html', alerts=alerts, stats=stats,
                           status=status, severity=severity, alert_type=alert_type)


@alerts_bp.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
@login_required
def resolve_alert(alert_id):
    """Marchează o alertă ca rezolvată."""
    alert = Alert.query.get_or_404(alert_id)
    alert.status = 'resolved'
    db.session.commit()

    flash(f'Alerta #{alert_id} a fost marcată ca rezolvată.', 'success')
    return redirect(request.referrer or url_for('alerts.index'))


@alerts_bp.route('/alerts/<int:alert_id>/dismiss', methods=['POST'])
@login_required
def dismiss_alert(alert_id):
    """Respinge o alertă (fals pozitiv)."""
    alert = Alert.query.get_or_404(alert_id)
    alert.status = 'dismissed'
    db.session.commit()

    flash(f'Alerta #{alert_id} a fost respinsă.', 'info')
    return redirect(request.referrer or url_for('alerts.index'))


@alerts_bp.route('/alerts/<int:alert_id>/block', methods=['POST'])
@login_required
def block_ip(alert_id):
    """Blochează IP-ul (și MAC-ul dacă este cunoscut) asociat cu o alertă."""
    # Doar adminii pot bloca
    if not current_user.is_admin():
        flash('Nu ai permisiunea de a bloca IP-uri.', 'danger')
        return redirect(url_for('alerts.index'))

    alert = Alert.query.get_or_404(alert_id)

    # Verificăm dacă IP-ul nu este deja blocat
    existing = BlockedIP.query.filter_by(ip_address=alert.source_ip, is_active=True).first()
    if existing:
        flash(f'IP-ul {alert.source_ip} este deja blocat.', 'warning')
        return redirect(request.referrer or url_for('alerts.index'))

    # Blocăm IP-ul
    blocked = BlockedIP(
        ip_address=alert.source_ip,
        reason=f'Blocat automat din alertă: {alert.alert_type} - {alert.message}',
        blocked_by=current_user.username
    )
    db.session.add(blocked)

    # Marcăm alerta ca rezolvată
    alert.status = 'resolved'
    alert.is_blocked = True

    # Salvăm log
    log = SecurityLog(
        event_type='ip_blocked',
        source_ip=alert.source_ip,
        message=f'IP {alert.source_ip} blocat de {current_user.username} (alertă #{alert_id})',
        severity='warning'
    )
    db.session.add(log)

    # Căutăm MAC-ul dispozitivului și îl blocăm dacă există
    device = NetworkDevice.query.filter_by(ip_address=alert.source_ip).first()
    mac_blocked = False
    blocked_mac_addr = None
    if device and device.mac_address:
        from app.ids.detector import _is_randomized_mac
        mac = device.mac_address.upper()
        if not _is_randomized_mac(mac):
            existing_mac = BlockedMAC.query.filter_by(mac_address=mac, is_active=True).first()
            if not existing_mac:
                blocked_mac = BlockedMAC(
                    mac_address=mac,
                    reason=f'Blocat din alertă #{alert_id}: {alert.alert_type} - {alert.message}',
                    blocked_by=current_user.username,
                    associated_ip=alert.source_ip,
                )
                db.session.add(blocked_mac)
                mac_blocked = True
                blocked_mac_addr = mac

    db.session.commit()

    # Dacă MikroTik este configurat, blochează pe router
    mikrotik = getattr(current_app, 'mikrotik_client', None)
    if mikrotik and mikrotik.is_connected():
        comment = f'Blocat din SchoolSec de {current_user.username}'
        if mac_blocked:
            success = mikrotik.block_mac_on_router(blocked_mac_addr, comment=comment)
            if success:
                flash(f'MAC-ul {blocked_mac_addr} a fost blocat și pe routerul MikroTik.', 'info')
        else:
            success = mikrotik.block_ip_on_router(alert.source_ip, comment=comment)
            if success:
                flash(f'IP-ul {alert.source_ip} a fost blocat și pe routerul MikroTik.', 'info')

    if mac_blocked:
        flash(f'IP-ul {alert.source_ip} și MAC-ul {blocked_mac_addr} au fost blocate cu succes.', 'success')
    else:
        flash(f'IP-ul {alert.source_ip} a fost blocat cu succes.', 'success')
    return redirect(request.referrer or url_for('alerts.index'))


@alerts_bp.route('/blocked-ips')
@login_required
def blocked_ips():
    """Pagina cu lista IP-urilor blocate."""
    ips = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    return render_template('blocked_ips.html', blocked_ips=ips)


@alerts_bp.route('/blocked-ips/<int:ip_id>/unblock', methods=['POST'])
@login_required
def unblock_ip(ip_id):
    """Deblochează un IP (și MAC-ul asociat dacă există)."""
    if not current_user.is_admin():
        flash('Nu ai permisiunea de a debloca IP-uri.', 'danger')
        return redirect(url_for('alerts.blocked_ips'))

    blocked = BlockedIP.query.get_or_404(ip_id)
    blocked.is_active = False

    # Deblochează și MAC-ul asociat dacă există
    associated_mac = BlockedMAC.query.filter_by(
        associated_ip=blocked.ip_address, is_active=True
    ).first()
    if associated_mac:
        associated_mac.is_active = False

    db.session.commit()

    # Dacă MikroTik este configurat, deblochează și pe router
    mikrotik = getattr(current_app, 'mikrotik_client', None)
    if mikrotik and mikrotik.is_connected():
        if associated_mac:
            mikrotik.unblock_mac_on_router(associated_mac.mac_address)
        mikrotik.unblock_ip_on_router(blocked.ip_address)

    if associated_mac:
        flash(f'IP-ul {blocked.ip_address} și MAC-ul {associated_mac.mac_address} au fost deblocate.', 'success')
    else:
        flash(f'IP-ul {blocked.ip_address} a fost deblocat.', 'success')
    return redirect(url_for('alerts.blocked_ips'))


@alerts_bp.route('/blocked-macs')
@login_required
def blocked_macs():
    """Pagina cu lista MAC-urilor blocate."""
    macs = BlockedMAC.query.order_by(BlockedMAC.blocked_at.desc()).all()
    return render_template('blocked_macs.html', blocked_macs=macs)


@alerts_bp.route('/blocked-macs/<int:mac_id>/unblock', methods=['POST'])
@login_required
def unblock_mac(mac_id):
    """Deblochează un MAC."""
    if not current_user.is_admin():
        flash('Nu ai permisiunea de a debloca MAC-uri.', 'danger')
        return redirect(url_for('alerts.blocked_macs'))

    blocked = BlockedMAC.query.get_or_404(mac_id)
    blocked.is_active = False
    db.session.commit()

    # Dacă MikroTik este configurat, deblochează și pe router
    mikrotik = getattr(current_app, 'mikrotik_client', None)
    if mikrotik and mikrotik.is_connected():
        mikrotik.unblock_mac_on_router(blocked.mac_address)

    flash(f'MAC-ul {blocked.mac_address} a fost deblocat.', 'success')
    return redirect(url_for('alerts.blocked_macs'))


@alerts_bp.route('/alerts/dismiss-all', methods=['POST'])
@login_required
def dismiss_all():
    """Respinge toate alertele active."""
    if not current_user.is_admin():
        flash('Acces interzis.', 'danger')
        return redirect(url_for('alerts.index'))
    count = Alert.query.filter_by(status='active').update({'status': 'dismissed'})
    db.session.commit()
    flash(f'{count} alerte au fost respinse.', 'info')
    return redirect(url_for('alerts.index'))


@alerts_bp.route('/alerts/resolve-all', methods=['POST'])
@login_required
def resolve_all():
    """Marchează toate alertele active ca rezolvate."""
    if not current_user.is_admin():
        flash('Acces interzis.', 'danger')
        return redirect(url_for('alerts.index'))
    count = Alert.query.filter_by(status='active').update({'status': 'resolved'})
    db.session.commit()
    flash(f'{count} alerte au fost marcate ca rezolvate.', 'success')
    return redirect(url_for('alerts.index'))


@alerts_bp.route('/alerts/delete-resolved', methods=['POST'])
@login_required
def delete_resolved():
    """Șterge toate alertele rezolvate și respinse."""
    if not current_user.is_admin():
        flash('Acces interzis.', 'danger')
        return redirect(url_for('alerts.index'))
    count = Alert.query.filter(Alert.status.in_(['resolved', 'dismissed'])).delete(synchronize_session=False)
    db.session.commit()
    flash(f'{count} alerte au fost șterse.', 'success')
    return redirect(url_for('alerts.index'))


@alerts_bp.route('/api/alerts/recent')
@login_required
def api_recent_alerts():
    """API endpoint pentru alertele recente (AJAX)."""
    alerts = Alert.query.filter_by(status='active').order_by(
        Alert.timestamp.desc()
    ).limit(10).all()
    return jsonify([a.to_dict() for a in alerts])
