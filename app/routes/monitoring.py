"""
Blueprint Flask pentru API-ul de monitorizare a resurselor sistemului.
Expune endpoint-uri pentru starea discului, verificare și curățare manuală.
"""
import logging

from flask import Blueprint, jsonify
from flask_login import login_required, current_user

from app.monitoring.disk_monitor import disk_monitor

monitoring_bp = Blueprint('monitoring', __name__, url_prefix='/api/monitoring')

logger = logging.getLogger(__name__)


@monitoring_bp.route('/disk-status', methods=['GET'])
@login_required
def get_disk_status():
    """Returnează utilizarea curentă a discului."""
    try:
        status = disk_monitor.get_disk_status()
        return jsonify({
            'status': status,
            'thresholds': disk_monitor.thresholds
        })
    except Exception as e:
        logger.error(f"Error in get_disk_status: {e}")
        return jsonify({'error': 'Could not retrieve disk status'}), 500


@monitoring_bp.route('/disk-check', methods=['POST'])
@login_required
def check_disk():
    """Verifică discul și declanșează alerte dacă e necesar."""
    try:
        result = disk_monitor.check_and_alert()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in check_disk: {e}")
        return jsonify({'error': 'Could not perform disk check'}), 500


@monitoring_bp.route('/disk-cleanup', methods=['POST'])
@login_required
def manual_cleanup():
    """Declanșează manual curățarea discului (doar admin)."""
    if not current_user.is_admin():
        return jsonify({'error': 'Admin only'}), 403

    try:
        result = disk_monitor.check_and_alert()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in manual_cleanup: {e}")
        return jsonify({'error': 'Could not perform disk cleanup'}), 500
