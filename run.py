"""
Punctul de intrare al aplicației de securitate pentru rețeaua școlii.
Rulați cu: python run.py
"""
import os
import signal
import subprocess
import sys
from app import create_app
from app.ids.sniffer import start_sniffer

# ---------------------------------------------------------------------------
# SIGTERM handler – graceful shutdown + start systemd service if requested
# ---------------------------------------------------------------------------
_SERVICE_FLAG = '/tmp/.schoolsec_start_service'
_SERVICE_NAME = 'schoolsec'


def _handle_sigterm(signum, frame):
    """Graceful shutdown la SIGTERM.

    Dacă există flag-ul /tmp/.schoolsec_start_service (creat de endpoint-ul
    stop-and-install), pornește serviciul systemd *după* ce procesul Flask s-a
    oprit (Popen detached).
    """
    print('[SchoolSec] SIGTERM primit – oprire graceful Flask...')
    if os.path.exists(_SERVICE_FLAG):
        try:
            os.remove(_SERVICE_FLAG)
        except OSError:
            pass
        # Launch `systemctl start` as a detached background process so that
        # it runs *after* this process exits and the port is freed.
        try:
            subprocess.Popen(
                ['bash', '-c', f'sleep 2 && sudo systemctl start {_SERVICE_NAME}'],
                close_fds=True,
                start_new_session=True,
            )
            print(f'[SchoolSec] Serviciul {_SERVICE_NAME} va fi pornit de systemd în 2s.')
        except Exception as exc:
            print(f'[SchoolSec] Avertisment: nu s-a putut planifica pornirea serviciului: {exc}')
    sys.exit(0)


signal.signal(signal.SIGTERM, _handle_sigterm)


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

    # Detectăm dacă sunt disponibile certificate SSL/TLS
    ssl_cert = app.config.get('SSL_CERT', '')
    ssl_key = app.config.get('SSL_KEY', '')
    ssl_context = None
    if ssl_cert and ssl_key and os.path.isfile(ssl_cert) and os.path.isfile(ssl_key):
        ssl_context = (ssl_cert, ssl_key)

    port = int(os.environ.get('PORT', 5000))
    protocol = 'https' if ssl_context else 'http'

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
    if ssl_context:
        print(f"  🔒 HTTPS activ cu certificat: {ssl_cert}")
    else:
        print("  ⚠️  HTTPS dezactivat. Setați SSL_CERT și SSL_KEY pentru HTTPS.")
        print("     Generați un certificat auto-semnat cu:")
        print("     openssl req -x509 -newkey rsa:4096 -nodes \\")
        print("       -out cert.pem -keyout key.pem -days 365 -subj \"/CN=localhost\"")
    print(f"  Acces: {protocol}://localhost:{port}")
    print("  ⚠️  Credențiale implicite: admin / Admin123 — schimbați-le!")
    print("=" * 60)

    # Pornim serverul Flask (cu sau fără SSL)
    app.run(
        host='0.0.0.0',
        port=port,
        debug=app.config.get('DEBUG', False),
        ssl_context=ssl_context,
        use_reloader=False  # Dezactivăm reloader pentru a evita pornirea dublă a snifferului
    )
