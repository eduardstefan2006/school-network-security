"""
Rutele API pentru gestionarea listei albe de infrastructură.
Permite adminilor să adauge/editeze/șteargă IP-uri de infrastructură
care nu trebuie niciodată blocate de sistemul de securitate.
"""
import logging
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user
from app.models import InfrastructureWhitelist
from app import db

infrastructure_bp = Blueprint('infrastructure', __name__, url_prefix='/api/infrastructure')
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pagina HTML de administrare
# ---------------------------------------------------------------------------

@infrastructure_bp.route('/whitelist/page')
@login_required
def whitelist_page():
    """Pagina de administrare a listei albe de infrastructură."""
    if not current_user.is_admin():
        from flask import abort
        abort(403)
    return render_template('infrastructure_whitelist.html')


# ---------------------------------------------------------------------------
# API REST
# ---------------------------------------------------------------------------

@infrastructure_bp.route('/whitelist', methods=['GET'])
@login_required
def get_whitelist():
    """Returnează toate intrările din lista albă de infrastructură."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis. Necesită privilegii de administrator.'}), 403

    entries = InfrastructureWhitelist.query.order_by(InfrastructureWhitelist.created_at.desc()).all()
    return jsonify({
        'whitelist': [entry.to_dict() for entry in entries],
        'count': len(entries),
    })


@infrastructure_bp.route('/whitelist', methods=['POST'])
@login_required
def add_whitelist():
    """Adaugă un IP în lista albă de infrastructură."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis. Necesită privilegii de administrator.'}), 403

    data = request.get_json(silent=True) or {}

    if not data.get('ip_address') or not data.get('service_type'):
        return jsonify({'error': 'ip_address și service_type sunt obligatorii'}), 400

    existing = InfrastructureWhitelist.query.filter_by(
        ip_address=data['ip_address']
    ).first()
    if existing:
        return jsonify({'error': 'IP-ul este deja în lista albă'}), 409

    entry = InfrastructureWhitelist(
        ip_address=data['ip_address'],
        hostname=data.get('hostname'),
        service_type=data['service_type'],
        description=data.get('description'),
        created_by=current_user.id,
    )
    db.session.add(entry)
    db.session.commit()

    logger.info('[Whitelist] Adăugat: %s de %s', entry.ip_address, current_user.username)

    return jsonify({
        'message': 'IP adăugat în lista albă',
        'entry': entry.to_dict(),
    }), 201


@infrastructure_bp.route('/whitelist/<int:entry_id>', methods=['PUT'])
@login_required
def update_whitelist(entry_id):
    """Actualizează o intrare din lista albă de infrastructură."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis. Necesită privilegii de administrator.'}), 403

    entry = db.session.get(InfrastructureWhitelist, entry_id)
    if entry is None:
        return jsonify({'error': 'Intrarea nu a fost găsită'}), 404

    data = request.get_json(silent=True) or {}

    if 'hostname' in data:
        entry.hostname = data['hostname']
    if 'description' in data:
        entry.description = data['description']
    if 'is_active' in data:
        entry.is_active = bool(data['is_active'])

    entry.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    logger.info('[Whitelist] Actualizat: %s de %s', entry.ip_address, current_user.username)

    return jsonify({
        'message': 'Intrare actualizată',
        'entry': entry.to_dict(),
    })


@infrastructure_bp.route('/whitelist/<int:entry_id>', methods=['DELETE'])
@login_required
def delete_whitelist(entry_id):
    """Șterge un IP din lista albă de infrastructură."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis. Necesită privilegii de administrator.'}), 403

    entry = db.session.get(InfrastructureWhitelist, entry_id)
    if entry is None:
        return jsonify({'error': 'Intrarea nu a fost găsită'}), 404

    ip_address = entry.ip_address
    db.session.delete(entry)
    db.session.commit()

    logger.warning('[Whitelist] Șters: %s de %s', ip_address, current_user.username)

    return jsonify({'message': f'IP {ip_address} eliminat din lista albă'})


@infrastructure_bp.route('/check/<path:ip_address>', methods=['GET'])
@login_required
def check_infrastructure_ip(ip_address):
    """Verifică dacă un IP se află în lista albă de infrastructură."""
    entry = InfrastructureWhitelist.query.filter_by(
        ip_address=ip_address, is_active=True
    ).first()

    return jsonify({
        'ip_address': ip_address,
        'is_whitelisted': entry is not None,
        'entry': entry.to_dict() if entry else None,
    })


@infrastructure_bp.route('/init-defaults', methods=['POST'])
@login_required
def init_defaults():
    """Inițializează lista albă cu IP-urile implicite de infrastructură."""
    if not current_user.is_admin():
        return jsonify({'error': 'Acces interzis. Necesită privilegii de administrator.'}), 403

    from config import DEFAULT_INFRASTRUCTURE_WHITELIST

    added = 0
    skipped = 0

    for entry_data in DEFAULT_INFRASTRUCTURE_WHITELIST:
        existing = InfrastructureWhitelist.query.filter_by(
            ip_address=entry_data['ip_address']
        ).first()
        if existing:
            skipped += 1
            continue

        entry = InfrastructureWhitelist(
            ip_address=entry_data['ip_address'],
            hostname=entry_data.get('hostname'),
            service_type=entry_data['service_type'],
            description=entry_data.get('description'),
            created_by=current_user.id,
        )
        db.session.add(entry)
        added += 1

    db.session.commit()
    logger.info('[Whitelist] Inițializat: %d adăugate, %d existente', added, skipped)

    return jsonify({
        'message': 'Lista albă implicită inițializată',
        'added': added,
        'skipped': skipped,
    })
