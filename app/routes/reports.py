"""
Rutele pentru generarea rapoartelor PDF.
"""
import io
from datetime import datetime, timezone, timedelta

from flask import Blueprint, render_template, request, send_file, flash, redirect, url_for
from flask_login import login_required

from app.models import Alert
from app.reports.pdf_generator import generate_report

reports_bp = Blueprint('reports', __name__)

_PERIOD_LABELS = {
    '24h': 'Ultimele 24 de ore',
    '7d': 'Ultimele 7 zile',
    '30d': 'Ultimele 30 de zile',
    'all': 'Toată perioada',
}


def _get_period_start(period):
    """Returnează timestamp-ul de start pentru perioada dată."""
    now = datetime.now(timezone.utc)
    if period == '24h':
        return now - timedelta(hours=24)
    elif period == '7d':
        return now - timedelta(days=7)
    elif period == '30d':
        return now - timedelta(days=30)
    return None  # 'all'


@reports_bp.route('/reports')
@login_required
def index():
    """Pagina de rapoarte cu opțiuni de generare."""
    return render_template('reports.html')


@reports_bp.route('/api/reports/generate', methods=['POST'])
@login_required
def generate():
    """Generează și descarcă un raport PDF."""
    period = request.form.get('period', '7d')
    if period not in _PERIOD_LABELS:
        period = '7d'

    period_start = _get_period_start(period)
    query = Alert.query
    if period_start is not None:
        query = query.filter(Alert.timestamp >= period_start)
    alerts = query.order_by(Alert.timestamp.desc()).all()

    period_label = _PERIOD_LABELS[period]

    try:
        pdf_bytes = generate_report(alerts, period_label)
    except Exception as exc:
        flash(f'Eroare la generarea raportului: {exc}', 'danger')
        return redirect(url_for('reports.index'))

    filename = f'schoolsec_raport_{datetime.now(timezone.utc).strftime("%Y-%m-%d")}.pdf'

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename,
    )
