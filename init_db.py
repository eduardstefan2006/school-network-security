"""
Script de inițializare a bazei de date.
Creează structura tabelelor și adaugă utilizatorul admin implicit.

Rulați o singură dată înainte de prima pornire:
    python init_db.py
"""
from app import create_app, db
from app.models import User, Alert, SecurityLog, BlockedIP, BlockedMAC, BlockedHostname, NetworkDevice


def init_database():
    """Inițializează baza de date cu date implicite."""
    app = create_app('default')

    with app.app_context():
        print("Creez structura bazei de date...")
        db.create_all()
        print("✓ Tabele create cu succes.")

        # Verificăm dacă există deja un utilizator admin
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            print("Creez utilizatorul admin implicit...")
            admin = User(
                username='admin',
                email='admin@scoala.ro',
                role='admin'
            )
            admin.set_password('Admin123')
            db.session.add(admin)

            # Adăugăm și un utilizator monitor pentru demonstrație
            monitor = User(
                username='monitor',
                email='monitor@scoala.ro',
                role='monitor'
            )
            monitor.set_password('monitor123')
            db.session.add(monitor)

            # Log de inițializare
            log = SecurityLog(
                event_type='system_init',
                message='Sistem de securitate inițializat. Utilizatori impliciți creați.',
                severity='info'
            )
            db.session.add(log)

            db.session.commit()
            print("✓ Utilizatori creați:")
            print("  - admin / Admin123 (Administrator)")
            print("  - monitor / monitor123 (Monitor)")
        else:
            print("✓ Utilizatorul admin există deja.")

        print()
        print("=" * 50)
        print("  Baza de date inițializată cu succes!")
        print("  Rulați aplicația cu: python run.py")
        print("=" * 50)


if __name__ == '__main__':
    init_database()
