"""
Punctul de intrare al aplicației de securitate pentru rețeaua școlii.
Rulați cu: python run.py
"""
import os
from app import create_app
from app.ids.sniffer import start_sniffer

# Creăm instanța aplicației
app = create_app(os.environ.get('FLASK_ENV', 'default'))

if __name__ == '__main__':
    # Pornim snifferul de rețea într-un thread separat
    start_sniffer(app)

    print("=" * 60)
    print("  SchoolSec - Sistem de Securitate pentru Rețeaua Școlii")
    print("=" * 60)
    print(f"  Mod: {'SIMULAT' if app.config['SIMULATION_MODE'] else 'REAL'}")
    print(f"  Debug: {app.config.get('DEBUG', False)}")
    print(f"  Baza de date: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print("  Acces: http://localhost:5000")
    print("  Credențiale implicite: admin / admin123")
    print("=" * 60)

    # Pornim serverul Flask
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=app.config.get('DEBUG', False),
        use_reloader=False  # Dezactivăm reloader pentru a evita pornirea dublă a snifferului
    )
