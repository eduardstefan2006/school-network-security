"""
Rutele pentru gestionarea utilizatorilor (doar pentru admini).
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.models import User, SecurityLog
from app import db
from app.utils import validate_password
from functools import wraps

users_bp = Blueprint('users', __name__)


def admin_required(f):
    """Decorator care verifică dacă utilizatorul curent este admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('Acces interzis. Necesită privilegii de administrator.', 'danger')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated_function


@users_bp.route('/users')
@login_required
@admin_required
def index():
    """Lista utilizatorilor (doar admin)."""
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=users)


@users_bp.route('/users/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    """Adaugă un utilizator nou."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'monitor')

        # Validare
        if not username or not password:
            flash('Numele de utilizator și parola sunt obligatorii.', 'danger')
            return render_template('users.html', users=User.query.all())

        valid, error_msg = validate_password(password)
        if not valid:
            flash(error_msg, 'danger')
            return render_template('users.html', users=User.query.all())

        # Verificăm dacă username-ul există deja
        if User.query.filter_by(username=username).first():
            flash(f'Utilizatorul "{username}" există deja.', 'danger')
            return redirect(url_for('users.index'))

        # Creăm utilizatorul
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)

        # Salvăm log
        log = SecurityLog(
            event_type='user_created',
            source_ip=request.remote_addr,
            message=f'Utilizator nou creat: {username} (rol: {role}) de {current_user.username}',
            severity='info'
        )
        db.session.add(log)
        db.session.commit()

        flash(f'Utilizatorul "{username}" a fost creat cu succes.', 'success')
        return redirect(url_for('users.index'))

    return render_template('users.html', users=User.query.all())


@users_bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_user(user_id):
    """Activează/dezactivează un utilizator."""
    user = User.query.get_or_404(user_id)

    # Nu permitem dezactivarea propriului cont
    if user.id == current_user.id:
        flash('Nu îți poți dezactiva propriul cont.', 'danger')
        return redirect(url_for('users.index'))

    user.is_active = not user.is_active
    status = 'activat' if user.is_active else 'dezactivat'
    db.session.commit()

    flash(f'Utilizatorul "{user.username}" a fost {status}.', 'success')
    return redirect(url_for('users.index'))


@users_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Șterge un utilizator."""
    user = User.query.get_or_404(user_id)

    # Nu permitem ștergerea propriului cont
    if user.id == current_user.id:
        flash('Nu îți poți șterge propriul cont.', 'danger')
        return redirect(url_for('users.index'))

    username = user.username
    db.session.delete(user)

    # Salvăm log
    log = SecurityLog(
        event_type='user_deleted',
        source_ip=request.remote_addr,
        message=f'Utilizator șters: {username} de {current_user.username}',
        severity='warning'
    )
    db.session.add(log)
    db.session.commit()

    flash(f'Utilizatorul "{username}" a fost șters.', 'success')
    return redirect(url_for('users.index'))


@users_bp.route('/users/<int:user_id>/change-password', methods=['POST'])
@login_required
@admin_required
def change_password(user_id):
    """Schimbă parola unui utilizator."""
    user = User.query.get_or_404(user_id)
    new_password = request.form.get('new_password', '')

    valid, error_msg = validate_password(new_password)
    if not valid:
        flash(error_msg, 'danger')
        return redirect(url_for('users.index'))

    user.set_password(new_password)
    db.session.commit()

    flash(f'Parola pentru "{user.username}" a fost schimbată.', 'success')
    return redirect(url_for('users.index'))
