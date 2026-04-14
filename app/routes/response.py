"""
Rutele API și paginile pentru sistemul de răspuns autonom (Faza 3).
Gestionează feedback-ul adminului, override-urile manuale și vizualizarea
istoricului de răspunsuri și a incidentelor.
"""
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user
from app import db
from app.models import (
    ResponseAction, ResponseFeedback, IncidentTicket, Alert,
)

response_bp = Blueprint('response', __name__)


# ---------------------------------------------------------------------------
# Pagini HTML
# ---------------------------------------------------------------------------

@response_bp.route('/incidents')
@login_required
def incidents():
    """Pagina cu ticketele de incident create automat."""
    status_filter = request.args.get('status', '')
    query = IncidentTicket.query
    if status_filter:
        query = query.filter_by(status=status_filter)
    incidents_list = query.order_by(IncidentTicket.created_at.desc()).all()

    counts = {
        'open': IncidentTicket.query.filter_by(status='open').count(),
        'investigating': IncidentTicket.query.filter_by(status='investigating').count(),
        'resolved': IncidentTicket.query.filter_by(status='resolved').count(),
    }
    return render_template('incidents.html', incidents=incidents_list,
                           counts=counts, status_filter=status_filter)


@response_bp.route('/response/history')
@login_required
def response_history():
    """Pagina cu istoricul tuturor acțiunilor de răspuns automat."""
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', '')
    query = ResponseAction.query
    if status_filter:
        query = query.filter_by(status=status_filter)
    actions = query.order_by(ResponseAction.created_at.desc()).paginate(
        page=page, per_page=25, error_out=False
    )

    # Mapăm fiecare acțiune cu feedback-ul corespunzător alertei
    feedback_map = {}
    for action in actions.items:
        if action.alert_id:
            fb = ResponseFeedback.query.filter_by(alert_id=action.alert_id).first()
            if fb:
                feedback_map[action.id] = fb

    return render_template('response_history.html', actions=actions,
                           feedback_map=feedback_map, status_filter=status_filter)


@response_bp.route('/response/feedback/<int:alert_id>', methods=['GET'])
@login_required
def feedback_form(alert_id):
    """Formular pentru trimiterea feedback-ului adminului."""
    alert = db.session.get(Alert, alert_id)
    if not alert:
        flash('Alerta nu a fost găsită.', 'danger')
        return redirect(url_for('alerts.index'))

    existing_feedback = ResponseFeedback.query.filter_by(alert_id=alert_id).first()
    return render_template('feedback_form.html', alert=alert,
                           existing_feedback=existing_feedback)


# ---------------------------------------------------------------------------
# API JSON
# ---------------------------------------------------------------------------

@response_bp.route('/api/response/feedback/<int:alert_id>', methods=['POST'])
@login_required
def submit_feedback(alert_id):
    """Trimite feedback-ul adminului pentru un răspuns automat."""
    data = request.get_json(silent=True) or {}
    feedback_type = data.get('type') or request.form.get('feedback_type', '')
    admin_comment = data.get('comment') or request.form.get('comment', '')

    if feedback_type not in ('confirmed', 'false_positive', 'partial'):
        return jsonify({'success': False, 'error': 'Tip de feedback invalid'}), 400

    from app.response.orchestrator import orchestrator
    feedback = orchestrator.feedback.record_feedback(
        alert_id=alert_id,
        feedback_type=feedback_type,
        admin_id=current_user.id,
        admin_comment=admin_comment or None,
    )

    if feedback is None:
        return jsonify({'success': False, 'error': 'Alerta nu a fost găsită'}), 404

    # Dacă cererea vine din formular HTML, redirecționăm
    if request.content_type and 'application/json' not in request.content_type:
        flash('Feedback înregistrat cu succes.', 'success')
        return redirect(url_for('alerts.index'))

    return jsonify({'success': True, 'feedback_id': feedback.id})


@response_bp.route('/api/response/override/<int:action_id>', methods=['POST'])
@login_required
def override_response(action_id):
    """Permite adminului să anuleze manual o acțiune de răspuns automat."""
    if not current_user.is_admin():
        return jsonify({'success': False, 'error': 'Permisiuni insuficiente'}), 403

    action = db.session.get(ResponseAction, action_id)
    if not action:
        return jsonify({'success': False, 'error': 'Acțiunea nu a fost găsită'}), 404

    if action.status != 'active':
        return jsonify({'success': False, 'error': 'Acțiunea nu mai este activă'}), 400

    action.status = 'reverted'

    # Deblocăm resursa dacă a fost o acțiune de blocare
    if 'block' in action.action_type and action.target:
        from app.response.blocker import response_blocker
        response_blocker.unblock_target(action.target, action.action_type)

    db.session.commit()
    return jsonify({'success': True})


@response_bp.route('/api/incidents', methods=['GET'])
@login_required
def get_incidents():
    """Returnează lista de incidente deschise."""
    status = request.args.get('status', 'open')
    incidents_list = IncidentTicket.query.filter_by(status=status).order_by(
        IncidentTicket.created_at.desc()
    ).all()
    return jsonify({'incidents': [i.to_dict() for i in incidents_list]})


@response_bp.route('/api/incidents/<int:incident_id>/status', methods=['POST'])
@login_required
def update_incident_status(incident_id):
    """Actualizează starea unui incident (open → investigating → resolved)."""
    if not current_user.is_admin():
        return jsonify({'success': False, 'error': 'Permisiuni insuficiente'}), 403

    incident = db.session.get(IncidentTicket, incident_id)
    if not incident:
        return jsonify({'success': False, 'error': 'Incidentul nu a fost găsit'}), 404

    data = request.get_json(silent=True) or {}
    new_status = data.get('status', '')
    if new_status not in ('open', 'investigating', 'resolved'):
        return jsonify({'success': False, 'error': 'Status invalid'}), 400

    incident.status = new_status
    if new_status == 'resolved':
        incident.resolved_at = datetime.now(timezone.utc)

    db.session.commit()
    return jsonify({'success': True, 'incident': incident.to_dict()})


@response_bp.route('/api/response/metrics', methods=['GET'])
@login_required
def get_metrics():
    """Returnează metricile sistemului de răspuns."""
    hours = request.args.get('hours', 24, type=int)
    from app.response.orchestrator import orchestrator
    metrics = orchestrator.get_metrics(hours=hours)
    return jsonify(metrics)
