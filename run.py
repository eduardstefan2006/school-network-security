"""
Punctul de intrare al aplicației de securitate pentru rețeaua școlii.
Rulați cu: python run.py
"""
import os
from app import create_app
from app.ids.sniffer import start_sniffer

def _load_dotenv(dotenv_path='.env'):
    """Încarcă variabilele din fișierul .env fără dependințe externe."""
    if not os.path.isfile(dotenv_path):
        return
    with open(dotenv_path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            # Ignorăm liniile goale și comentariile
            if not line or line.startswith('#'):
                continue
            # Suportăm formatul KEY=VALUE (cu sau fără ghilimele)
            if '=' not in line:
                continue
            key, _, value = line.partition('=')
            key = key.strip()
            value = value.strip()
            # Eliminăm ghilimelele opționale din jurul valorii
            if len(value) >= 2 and value[0] in ('"', "'") and value[-1] == value[0]:
                value = value[1:-1]
            # Setăm variabila doar dacă nu e deja setată în mediu
            if key and key not in os.environ:
                os.environ[key] = value


# Încărcăm .env înainte de orice altceva
_load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

# Creăm instanța aplicației
app = create_app(os.environ.get('FLASK_ENV', 'default'))

if __name__ == '__main__':
    # Pornim snifferul de rețea într-un thread separat
    start_sniffer(app)

    print("=" * 60)
    print("  SchoolSec - Sistem de Securitate pentru Rețeaua Școlii")
    print("=" * 60)
    sniffer_mode = app.config.get('SNIFFER_MODE', 'simulated')
    simulation_mode = app.config.get('SIMULATION_MODE', True)
    if sniffer_mode == 'simulated' and not simulation_mode:
        sniffer_mode = 'interface'
    print(f"  Mod sniffer: {sniffer_mode.upper()}")
    print(f"  Debug: {app.config.get('DEBUG', False)}")
    print(f"  Baza de date: {app.config['SQLALCHEMY_DATABASE_URI']}")
    mikrotik_enabled = app.config.get('MIKROTIK_ENABLED', False)
    mikrotik_host = app.config.get('MIKROTIK_HOST', '')
    if mikrotik_enabled and mikrotik_host:
        print(f"  MikroTik: {mikrotik_host} (ACTIVAT)")
    else:
        print(f"  MikroTik: DEZACTIVAT")
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
