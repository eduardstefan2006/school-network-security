"""
Rutele pentru autentificare (login/logout).
"""
import hmac
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


@auth_bp.route('/profile/change-password', methods=['GET', 'POST'])
@login_required
def change_own_password():
    """Permite utilizatorului logat să-și schimbe propria parolă."""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validare parola curentă
        if not current_user.check_password(current_password):
            flash('Parola curentă este incorectă.', 'danger')
            return redirect(url_for('auth.change_own_password'))

        # Validare parola nouă
        if not new_password or len(new_password) < 6:
            flash('Parola nouă trebuie să aibă cel puțin 6 caractere.', 'danger')
            return redirect(url_for('auth.change_own_password'))

        if new_password != confirm_password:
            flash('Parolele noi nu coincid.', 'danger')
            return redirect(url_for('auth.change_own_password'))

        if hmac.compare_digest(current_password, new_password):
            flash('Parola nouă trebuie să fie diferită de cea curentă.', 'danger')
            return redirect(url_for('auth.change_own_password'))

        # Schimbă parola
        current_user.set_password(new_password)
        db.session.commit()

        # Log de securitate
        try:
            log = SecurityLog(
                event_type='password_changed',
                source_ip=request.remote_addr,
                message=f'Utilizatorul {current_user.username} și-a schimbat parola.',
                severity='info'
            )
            db.session.add(log)
            db.session.commit()
        except Exception:
            db.session.rollback()

        flash('Parola a fost schimbată cu succes!', 'success')
        return redirect(url_for('dashboard.index'))

    return render_template('change_password.html')


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
