"""
Rutele pentru autentificare (login/logout).
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app.models import User, SecurityLog
from app import db

# Creăm blueprint-ul pentru autentificare
auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Pagina de autentificare."""
    # Dacă utilizatorul este deja autentificat, redirecționăm la dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False) == 'on'

        # Căutăm utilizatorul în baza de date
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password) and user.is_active:
            login_user(user, remember=remember)

            # Salvăm log-ul de autentificare reușită
            log = SecurityLog(
                event_type='user_login',
                source_ip=request.remote_addr,
                message=f"Autentificare reușită pentru utilizatorul: {username}",
                severity='info'
            )
            db.session.add(log)
            db.session.commit()

            flash(f'Bine ai venit, {user.username}!', 'success')

            # Redirecționăm către pagina solicitată inițial sau dashboard
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard.index'))
        else:
            # Salvăm log-ul de autentificare eșuată
            log = SecurityLog(
                event_type='login_failed',
                source_ip=request.remote_addr,
                message=f"Autentificare eșuată pentru utilizatorul: {username}",
                severity='warning'
            )
            db.session.add(log)
            db.session.commit()

            flash('Nume de utilizator sau parolă incorectă.', 'danger')

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """Deconectarea utilizatorului."""
    username = current_user.username

    # Salvăm log-ul de deconectare
    log = SecurityLog(
        event_type='user_logout',
        source_ip=request.remote_addr,
        message=f"Utilizatorul {username} s-a deconectat.",
        severity='info'
    )
    db.session.add(log)
    db.session.commit()

    logout_user()
    flash('Te-ai deconectat cu succes.', 'info')
    return redirect(url_for('auth.login'))
