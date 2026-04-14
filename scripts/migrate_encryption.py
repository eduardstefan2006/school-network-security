"""
Script de migrare one-time pentru criptarea credențialelor MikroTik existente.

Dacă în baza de date există un MikroTikConfig cu parola stocată în câmpul
`password_encrypted` (care nu este încă criptat), sau dacă vrei să re-criptezi
cu cheia curentă, rulați acest script o singură dată:

    python scripts/migrate_encryption.py

Scriptul detectează automat dacă parola din BD este deja un token Fernet valid
(nu necesită re-criptare) sau text plain (necesită criptare).
"""
import sys
import os

# Adăugăm directorul rădăcină al proiectului în path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models import MikroTikConfig
from app.encryption import encrypt_value, decrypt_value


def migrate_mikrotik_password():
    """Criptează parola MikroTik dacă este stocată ca text plain."""
    app = create_app('default')
    with app.app_context():
        cfg = db.session.get(MikroTikConfig, 1)
        if cfg is None:
            print('[Migrare] Nicio configurație MikroTik găsită în baza de date. Nimic de migrat.')
            return

        secret_key = app.config['SECRET_KEY']

        if not cfg.password_encrypted:
            print('[Migrare] Câmpul password_encrypted este gol. Nimic de migrat.')
            return

        # Verificăm dacă e deja un token Fernet valid
        try:
            decrypt_value(cfg.password_encrypted, secret_key)
            print('[Migrare] Parola este deja criptată cu Fernet. Nu este nevoie de migrare.')
            return
        except (ValueError, Exception):
            pass  # Nu este token Fernet valid → presupunem text plain

        # Criptăm parola plain text
        plain_password = cfg.password_encrypted
        try:
            encrypted = encrypt_value(plain_password, secret_key)
            cfg.password_encrypted = encrypted
            db.session.commit()
            print(f'[Migrare] Parola MikroTik pentru host={cfg.host} a fost criptată cu succes.')
        except Exception as exc:
            db.session.rollback()
            print(f'[Migrare] EROARE la criptarea parolei: {exc}')
            sys.exit(1)


if __name__ == '__main__':
    migrate_mikrotik_password()
