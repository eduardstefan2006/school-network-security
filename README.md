# SchoolSec - Sistem de Securitate pentru Rețeaua Școlii

> **Aplicație educațională** pentru monitorizarea și securizarea rețelei unei școli, construită cu Python (Flask + Scapy).

---

## 📋 Descriere

**SchoolSec** este un sistem complet de securitate pentru rețeaua școlii care oferă:

- **Monitorizare trafic** în timp real cu capturarea pachetelor (Scapy)
- **Detectare intruziuni (IDS)** - port scanning, brute force, trafic anormal
- **Dashboard web** modern cu Bootstrap 5 și actualizare live
- **Sistem de autentificare** cu roluri (Admin și Monitor)
- **Loguri de securitate** cu export CSV
- **Modul simulat** pentru testare pe Windows fără privilegii root
- **Integrare MikroTik RouterOS API** - control direct al router-ului, auto-descoperire VLAN-uri, blocare IP-uri

---

## 🏗️ Arhitectura de Implementare

### Evoluția arhitecturii: de la Port Mirroring la TZSP + API

> **⚠️ Port mirroring NU este obligatoriu!** Serverul SchoolSec poate fi instalat **oriunde pe rețea** și nu are nevoie de o conexiune fizică directă la routerul MikroTik.

#### Abordarea veche (Port Mirroring / SPAN)

În varianta inițială, serverul trebuia conectat fizic la un port special al routerului configurat cu SPAN (Switched Port ANalyzer), iar pachetele erau capturate direct de pe interfața de rețea:

```
[Internet] → [Router MikroTik]
                    │
              Port SPAN/Mirror
                    │
             [Server SchoolSec]  ← trebuia conectat fizic
             (captură directă de pachete)
```

**Limitări:** serverul era legat de locația fizică a routerului, nu putea fi mutat, iar controlul era doar pasiv (observare).

#### Arhitectura nouă (TZSP + RouterOS API)

Acum SchoolSec funcționează cu **două mecanisme independente și complementare**:

```
                    [Internet]
                        │
               [Router MikroTik]
              /         │        \
     TZSP UDP           │         RouterOS API (TCP)
   (streaming)          │         (control și date)
        │               │              │
        ▼               │              ▼
[Server SchoolSec] ←────┘    [Server SchoolSec]
 (oriunde pe rețea)           (oriunde pe rețea)
```

| Aspect | Port Mirroring (Vechi) | TZSP + API (Nou) |
|--------|------------------------|------------------|
| **Conexiune fizică** | ✅ Obligatorie | ❌ Nu e nevoie |
| **Locație server** | ❌ Trebuie pe segmentul mirrorat | ✅ Oriunde pe rețea |
| **Control router** | ❌ Doar observare trafic | ✅ Comandă directă prin API |
| **Descoperire VLAN-uri** | ❌ Doar ce se mirrorează | ✅ Auto-descoperire din DHCP |
| **Blocare automată IP** | ❌ N/A | ✅ Direct pe firewall-ul routerului |
| **Monitorizare health router** | ❌ N/A | ✅ CPU, RAM, uptime, interfețe |
| **Detectare atacuri externe** | ❌ N/A | ✅ Port scan, DDoS, brute force din internet |

### Cum funcționează TZSP (UDP Streaming)

RouterOS trimite o **copie a pachetelor** prin UDP la portul 37008 al serverului SchoolSec. Serverul ascultă pasiv — nu are nevoie de privilegii root (port > 1024) și nu trebuie să fie pe același segment de rețea.

```
Router MikroTik                    Server SchoolSec
┌─────────────────┐   UDP:37008   ┌─────────────────┐
│ /tool sniffer   │ ─────────────▶│ TZSP Listener   │
│ streaming=yes   │               │ port 37008      │
│ server=IP_SERVER│               │ (orice locație) │
└─────────────────┘               └─────────────────┘
```

### Cum funcționează RouterOS API (TCP Control)

SchoolSec se conectează **activ** prin TCP la API-ul RouterOS (port 8728 sau 8729 SSL) pentru a obține informații și a controla router-ul:

```
Server SchoolSec                   Router MikroTik
┌─────────────────┐   TCP:8728    ┌─────────────────┐
│ MikrotikClient  │ ─────────────▶│ RouterOS API    │
│ - get DHCP      │               │ - DHCP leases   │
│ - get conexiuni │◀─────────────│ - conexiuni     │
│ - blocare IP    │               │ - firewall      │
│ - loguri FW     │               │ - statistici    │
└─────────────────┘               └─────────────────┘
```

---

## 🗂️ Structura Proiectului

```
school-network-security/
├── app/
│   ├── __init__.py          # Factory Flask + extensii
│   ├── models.py            # Modele SQLite (User, Alert, Log, BlockedIP)
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── auth.py          # Login/logout
│   │   ├── dashboard.py     # Dashboard + loguri + export CSV
│   │   ├── alerts.py        # Gestionare alerte + IP-uri blocate
│   │   └── users.py         # Gestionare utilizatori (admin)
│   ├── ids/
│   │   ├── __init__.py
│   │   ├── sniffer.py       # Captură trafic (Scapy sau simulat)
│   │   ├── detector.py      # Logica IDS de detectare
│   │   └── rules.py         # Reguli configurabile
│   ├── static/
│   │   ├── css/style.css    # Stiluri dark theme
│   │   └── js/dashboard.js  # Actualizare live + grafice
│   └── templates/
│       ├── base.html        # Template de bază cu navbar
│       ├── login.html       # Pagina de autentificare
│       ├── dashboard.html   # Dashboard principal
│       ├── alerts.html      # Lista de alerte
│       ├── logs.html        # Loguri de securitate
│       ├── users.html       # Gestionare utilizatori
│       └── blocked_ips.html # IP-uri blocate
├── config.py                # Configurare aplicație
├── run.py                   # Punct de intrare
├── init_db.py               # Inițializare bază de date
├── requirements.txt         # Dependențe Python
└── README.md
```

---

## 🚀 Instalare și Rulare

### Cerințe

- Python 3.10+
- pip

### Cerințe de Sistem

#### Minimum (modul simulat / TZSP fără mirroring direct)

| Componentă | Cerință minimă |
|------------|---------------|
| **CPU** | 2 core (Pentium, ARM, etc.) |
| **RAM** | 1 GB (512 MB pentru modul simulat) |
| **Spațiu disk** | 500 MB (bază de date SQLite) |
| **Rețea** | Conector Ethernet (pentru TZSP de la router) |
| **OS** | Linux (Debian/Ubuntu), macOS, Windows (modul simulat) |
| **Python** | 3.10+ |

#### Recomandat (producție cu TZSP + RouterOS API)

| Componentă | Cerință recomandată |
|------------|---------------------|
| **CPU** | 4 core (Intel i5/i7, ARM Cortex A53+) |
| **RAM** | 4 GB (minimum 2 GB pentru bază de date mai mare) |
| **Spațiu disk** | 10–20 GB (pentru istoric loguri și alerte) |
| **Rețea** | Gigabit Ethernet |
| **OS** | Linux (Debian 11+, Ubuntu 20.04+) |
| **Python** | 3.10+ |
| **Bază de date** | PostgreSQL 12+ (opțional, în locul SQLite) |

#### Cu modul interface (captură directă pe interfață)

| Componentă | Cerință |
|------------|---------|
| **CPU** | 4+ core (pentru procesare realtime) |
| **RAM** | 8 GB |
| **Rețea** | Gigabit Ethernet + port mirror/SPAN configurat |
| **OS** | Linux (doar) |
| **Privilegii** | root (sudo) obligatoriu |

### Tabel comparativ moduri de funcționare

| Mod | CPU | RAM | Disk | Rețea | OS | Root | Utilizare |
|-----|-----|-----|------|-------|----|------|-----------|
| **Simulat** | 2 core | 512 MB | 500 MB | Nu e necesar | Windows/macOS/Linux | Nu | Demo/test |
| **TZSP** | 2 core | 1 GB | 1–5 GB | Gigabit (UDP 37008) | Linux | Nu | Producție, flexibil |
| **Interface** | 4+ core | 8 GB | 10–20 GB | Gigabit + SPAN | Linux | Da | Captură directă |
| **TZSP + API** | 4 core | 4 GB | 10–20 GB | Gigabit | Linux | Nu | **Recomandat** |

> **Notă disk TZSP vs TZSP + API:** Modul TZSP + API stochează suplimentar istoricul DHCP leases, conexiunile active, statisticile interfețelor și logurile firewall (necesare pentru detectarea atacurilor externe), ceea ce crește semnificativ volumul de date față de modul TZSP simplu.

### Dependențe de sistem (nu doar Python)

Pe sisteme Linux, instalați dependențele de sistem înainte de `pip install`:

```bash
sudo apt update
sudo apt install -y \
    libffi-dev \
    libssl-dev \
    python3-dev \
    libpcap-dev
```

| Pachet | Rol |
|--------|-----|
| `libffi-dev` | Necesar pentru biblioteca `cryptography` (TLS/SSL) |
| `libssl-dev` | Header-uri OpenSSL pentru operații criptografice |
| `python3-dev` | Header-uri Python necesare la compilarea extensiilor C |
| `libpcap-dev` | Suport pcap pentru Scapy (captură pachete în modul `interface`) |

### Instalare

```bash
# 1. Clonează repository-ul
git clone https://github.com/eduardstefan2006/school-network-security.git
cd school-network-security

# 2. Creează un mediu virtual
python -m venv venv

# Windows:
venv\Scripts\activate

# Linux/Mac:
source venv/bin/activate

# 3. Instalează dependențele
pip install -r requirements.txt

# 4. Configurează variabilele de mediu
cp .env.example .env
# Editați .env și completați valorile necesare (SECRET_KEY, MikroTik etc.)

# 5. Inițializează baza de date
python init_db.py

# 5b. (Opțional) Dacă ai o bază de date existentă, rulează migrarea pentru a adăuga coloane noi
python scripts/migrate_db.py

# 6. Pornește aplicația
python run.py
```

### Accesare

Deschide browserul la: **http://localhost:5000**

Credențiale implicite:
- **Admin**: `admin` / `admin123`
- **Monitor**: `monitor` / `monitor123`

---

## ⚙️ Configurare

### Modul Simulat (implicit)

Aplicația pornește implicit în **modul simulat** - generează trafic fictiv pentru demonstrație, fără a necesita Scapy sau privilegii root.

### Modul Real (Linux cu privilegii root)

```bash
# Dezactivează modul simulat
export SNIFFER_MODE=interface

# Specifică interfața de rețea (opțional)
export NETWORK_INTERFACE=eth0

# Rulează cu sudo pentru captură de pachete
sudo python run.py
```

### Modul TZSP (MikroTik streaming)

```bash
export SNIFFER_MODE=tzsp
python run.py
```

### Variabile de Mediu

| Variabilă | Implicit | Descriere |
|-----------|----------|-----------|
| `FLASK_ENV` | `default` | Mediul de execuție (`development`, `production`) |
| `SECRET_KEY` | (valoare implicită) | Cheia secretă pentru sesiuni Flask |
| `DATABASE_URL` | `sqlite:///security.db` | URI baza de date (SQLite sau PostgreSQL) |
| `SIMULATION_MODE` | `true` | Modul simulat (fără Scapy) - deprecat, folosiți `SNIFFER_MODE` |
| `SNIFFER_MODE` | `simulated` | Modul sniffer: `simulated`, `interface`, sau `tzsp` |
| `NETWORK_INTERFACE` | auto | Interfața de rețea pentru captură (modul `interface`) |
| `TZSP_LISTEN_ADDRESS` | `0.0.0.0` | Adresa IP pe care ascultă listener-ul TZSP |
| `TZSP_PORT` | `37008` | Portul UDP pentru primirea pachetelor TZSP de la MikroTik |
| `PORT` | `5000` | Portul serverului web |
| `SSL_CERT` | `` | Calea spre fișierul certificat SSL/TLS (ex: `cert.pem`) |
| `SSL_KEY` | `` | Calea spre fișierul cheie privată SSL/TLS (ex: `key.pem`) |
| `MIKROTIK_ENABLED` | `false` | Activează integrarea cu MikroTik RouterOS API |
| `MIKROTIK_HOST` | `` | Adresa IP a router-ului MikroTik (ex: `192.168.88.1`) |
| `MIKROTIK_PORT` | `8728` | Portul API MikroTik (`8728` plaintext, `8729` SSL) |
| `MIKROTIK_USERNAME` | `` | Utilizatorul API MikroTik |
| `MIKROTIK_PASSWORD` | `` | Parola API MikroTik |
| `MIKROTIK_SYNC_INTERVAL` | `60` | Intervalul (secunde) pentru sincronizarea datelor din RouterOS API (DHCP, conexiuni, statistici) |
| `EXTERNAL_MONITOR_ENABLED` | `true` | Activează monitorizarea atacurilor externe din internet prin logurile firewall-ului MikroTik (activ automat când `MIKROTIK_ENABLED=true`) |

---

## 🔒 HTTPS și Securitate

### De ce HTTPS?

Fără HTTPS, credențialele și datele de sesiune sunt transmise în text simplu și pot fi interceptate (atac MITM). Cu HTTPS:

- ✅ Comunicarea este **criptată end-to-end**
- ✅ Cookie-ul de sesiune are flag `Secure` (nu se trimite pe HTTP)
- ✅ Headers de securitate HTTP sunt activate automat

### Activare HTTPS local (certificat auto-semnat)

```bash
# 1. Generați certificat auto-semnat (valabil 365 zile)
openssl req -x509 -newkey rsa:4096 -nodes \
  -out cert.pem -keyout key.pem -days 365 \
  -subj "/CN=localhost"

# 2. Configurați .env
cp .env.example .env
# Editați .env și setați SSL_CERT=cert.pem, SSL_KEY=key.pem

# 3. Porniți aplicația
python run.py
# Acces: https://localhost:5000
```

> Browserul va afișa un avertisment pentru certificatul auto-semnat — este normal în development. Adăugați o excepție sau importați cert.pem ca autoritate de certificare locală.

### Activare HTTPS în producție (Let's Encrypt)

```bash
# 1. Instalați certbot
sudo apt install certbot

# 2. Obțineți certificat (necesită domeniu public)
sudo certbot certonly --standalone -d domeniu.scoala.ro

# 3. Configurați .env
SSL_CERT=/etc/letsencrypt/live/domeniu.scoala.ro/fullchain.pem
SSL_KEY=/etc/letsencrypt/live/domeniu.scoala.ro/privkey.pem
FLASK_ENV=production
SECRET_KEY=<cheie-aleatorie-puternica>
```

### Generare SECRET_KEY sigură

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### Headers de securitate HTTP activate automat

La fiecare răspuns, aplicația adaugă automat:

| Header | Valoare | Protecție |
|--------|---------|-----------|
| `Strict-Transport-Security` | `max-age=31536000` | Forțează HTTPS |
| `X-Content-Type-Options` | `nosniff` | Previne MIME sniffing |
| `X-Frame-Options` | `DENY` | Previne clickjacking |
| `Content-Security-Policy` | (restricționat) | Previne XSS |
| `Cache-Control` | `no-store` | Nu memorează date sensibile |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limitează referrer |

### Schimbarea credențialelor implicite

```bash
# Login cu admin / admin123 la https://localhost:5000
# Mergeți la Setări → Utilizatori → Schimbați parola
```

> ⚠️ **Obligatoriu în producție:** schimbați parola `admin` și `monitor` imediat după instalare!

---

## 🔔 Notificări Telegram

SchoolSec poate trimite notificări instant pe Telegram atunci când IDS-ul detectează alerte critice sau de severitate ridicată.

### Creare bot Telegram

1. Deschide Telegram și caută **@BotFather**
2. Trimite comanda `/newbot` și urmează instrucțiunile
3. BotFather îți va oferi un **token** de forma `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`

### Obținere Chat ID

1. Adaugă bot-ul în grupul/chat-ul dorit (sau începe o conversație privată)
2. Trimite un mesaj în acel chat
3. Accesează `https://api.telegram.org/bot<TOKEN>/getUpdates` în browser
4. Găsește câmpul `"chat": {"id": ...}` — acesta este **Chat ID**-ul

### Variabile de mediu

| Variabilă | Implicit | Descriere |
|-----------|----------|-----------|
| `TELEGRAM_ENABLED` | `false` | Activează notificările Telegram (`true`/`false`) |
| `TELEGRAM_BOT_TOKEN` | `` | Token-ul bot-ului Telegram |
| `TELEGRAM_CHAT_ID` | `` | ID-ul chat-ului/grupului unde se trimit notificările |
| `TELEGRAM_MIN_SEVERITY` | `critical` | Severitatea minimă pentru notificări: `low`, `medium`, `high`, `critical` |

### Exemplu de configurare

```bash
export TELEGRAM_ENABLED=true
export TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
export TELEGRAM_CHAT_ID=-1001234567890
export TELEGRAM_MIN_SEVERITY=critical
```

### Testare configurație

Folosind endpoint-ul dedicat (necesită autentificare ca administrator):

```bash
curl -X POST http://localhost:5000/api/telegram/test \
     -H "Content-Type: application/json" \
     --cookie "session=<sesiunea_ta>"
```

Sau direct din panoul web al administratorului.

### Actualizare serviciu systemd

Adaugă variabilele Telegram în fișierul `schoolsec.service`:

```ini
[Unit]
Description=SchoolSec Network Security Monitor
After=network.target

[Service]
User=schoolsec
WorkingDirectory=/opt/school-network-security
ExecStart=/opt/school-network-security/venv/bin/python run.py
Restart=always
Environment=FLASK_ENV=production
Environment=SNIFFER_MODE=tzsp
Environment=TZSP_LISTEN_ADDRESS=0.0.0.0
Environment=TZSP_PORT=37008
Environment=TELEGRAM_ENABLED=true
Environment=TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
Environment=TELEGRAM_CHAT_ID=-1001234567890
Environment=TELEGRAM_MIN_SEVERITY=critical

[Install]
WantedBy=multi-user.target
```

> **Rate limiting:** Maximum o notificare per combinație (IP sursă, tip alertă) la fiecare 5 minute, pentru a evita spam-ul.

---

## 🔌 Integrare MikroTik TZSP

### Ce este TZSP?

**TZSP** (TaZmen Sniffer Protocol) este un protocol care permite unui router MikroTik să trimită o copie a traficului de rețea către un server extern prin **UDP**. SchoolSec poate primi și analiza acest trafic fără a fi necesar:

- ❌ conexiune fizică directă la router
- ❌ port mirroring (SPAN) la nivel hardware
- ❌ privilegii root pe server (portul 37008 > 1024)

RouterOS inițiază streaming-ul și trimite pachetele prin rețea — serverul poate fi instalat **oriunde are conectivitate IP** cu routerul.

### Topologie rețea cu TZSP

```
         [Internet / WAN]
                │
        ┌───────┴──────────┐
        │  Router MikroTik │  192.168.88.1
        │  /tool sniffer   │
        │  streaming → ────┼──── UDP:37008 ──────┐
        └───────┬──────────┘                      │
                │ LAN                             ▼
        ┌───────┴──────────┐        ┌─────────────────────┐
        │  Switch / AP     │        │  Server SchoolSec   │
        └───────┬──────────┘        │  192.168.88.X       │
                │                   │  (orice loc pe LAN) │
        ┌───────┴──────────┐        └─────────────────────┘
        │  Dispozitive     │
        │  școlare         │
        └──────────────────┘
```

> **Notă:** Serverul NU trebuie conectat la un port SPAN/mirror al switch-ului. Poate fi pe orice segment de rețea care are acces UDP la portul 37008 al serverului.

### Configurare MikroTik

Pe routerul MikroTik (RouterOS), activați streaming-ul TZSP:

```routeros
/tool sniffer
set filter-interface=RETEA \
    streaming-enabled=yes \
    streaming-server=192.168.2.243 \
    filter-stream=yes
/tool sniffer start
```

Înlocuiți `RETEA` cu numele bridge-ului/interfeței dorite și `192.168.2.243` cu IP-ul mașinii pe care rulează SchoolSec.

### Rulare cu modul TZSP

```bash
# Setați modul TZSP
export SNIFFER_MODE=tzsp

# Opțional: personalizați adresa și portul de ascultare
export TZSP_LISTEN_ADDRESS=0.0.0.0
export TZSP_PORT=37008

# Porniți aplicația (nu necesită root, portul 37008 > 1024)
python run.py
```

### Exemplu fișier systemd (`schoolsec.service`)

```ini
[Unit]
Description=SchoolSec Network Security Monitor
After=network.target

[Service]
User=schoolsec
WorkingDirectory=/opt/school-network-security
ExecStart=/opt/school-network-security/venv/bin/python run.py
Restart=always
Environment=FLASK_ENV=production
Environment=SNIFFER_MODE=tzsp
Environment=TZSP_LISTEN_ADDRESS=0.0.0.0
Environment=TZSP_PORT=37008

[Install]
WantedBy=multi-user.target
```

---

## 🔗 Integrare Completă MikroTik (TZSP + API)

### Combinarea celor două mecanisme

TZSP și RouterOS API sunt **opționale, dar se completează** perfect:

| Mecanism | Protocol | Direcție | Funcție |
|----------|----------|----------|---------|
| **TZSP** | UDP:37008 | Router → Server | Streaming trafic intern (pachete capturate) |
| **RouterOS API** | TCP:8728/8729 | Server → Router | Control și date de management |

Când sunt active **ambele**, SchoolSec poate:
- 📦 Analiza traficul intern în timp real (TZSP)
- 🖥️ Sincroniza automat DHCP leases și mapa IP → hostname → VLAN (API)
- 🚫 Bloca automat IP-uri suspecte direct pe firewall-ul MikroTik (API)
- 🌐 Detecta atacuri din internet prin logurile firewall (API)
- 📊 Monitoriza sănătatea router-ului (CPU, RAM, uptime, trafic interfețe) (API)

### Detectare atacuri externe

Cu `EXTERNAL_MONITOR_ENABLED=true` (implicit când MikroTik este activ), SchoolSec analizează logurile firewall ale routerului pentru a detecta:

- **Port scanning** din internet (multe porturi lovite de același IP extern)
- **Brute force** pe servicii expuse (SSH, HTTP, RDP)
- **DDoS / flooding** — volume mari de conexiuni respinse

```
[Atacator extern]
       │ port scan / brute force
       ▼
[Router MikroTik]
       │ drop + log (firewall)
       │
       ▼ RouterOS API (loguri firewall)
[Server SchoolSec]
       │ analiză + alertă
       ▼
[Dashboard + Telegram]
```

### Configurare completă `.env`

```bash
# ── Sniffer ──────────────────────────────────────────
SNIFFER_MODE=tzsp
TZSP_LISTEN_ADDRESS=0.0.0.0
TZSP_PORT=37008

# ── RouterOS API ─────────────────────────────────────
MIKROTIK_ENABLED=true
MIKROTIK_HOST=192.168.88.1
MIKROTIK_PORT=8728          # sau 8729 pentru SSL
MIKROTIK_USERNAME=admin
MIKROTIK_PASSWORD=parola-router

# Sincronizare DHCP, conexiuni și statistici la fiecare 60 secunde
MIKROTIK_SYNC_INTERVAL=60

# Monitorizare atacuri externe prin loguri firewall
EXTERNAL_MONITOR_ENABLED=true

# ── Notificări ───────────────────────────────────────
TELEGRAM_ENABLED=true
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHAT_ID=-1001234567890
TELEGRAM_MIN_SEVERITY=high

# ── Securitate ───────────────────────────────────────
SECRET_KEY=<cheie-aleatorie-puternica>
FLASK_ENV=production
SSL_CERT=/etc/letsencrypt/live/domeniu.scoala.ro/fullchain.pem
SSL_KEY=/etc/letsencrypt/live/domeniu.scoala.ro/privkey.pem
```

### Exemplu fișier systemd complet (`schoolsec.service`)

```ini
[Unit]
Description=SchoolSec Network Security Monitor
After=network.target

[Service]
User=schoolsec
WorkingDirectory=/opt/school-network-security
ExecStart=/opt/school-network-security/venv/bin/python run.py
Restart=always
EnvironmentFile=/opt/school-network-security/.env

[Install]
WantedBy=multi-user.target
```

### Comenzi complete RouterOS pentru setup TZSP + API

```routeros
# 1. Activare API RouterOS (pentru integrarea SchoolSec)
/ip service enable api
/ip service set api port=8728

# 2. (Opțional) API cu SSL
/ip service enable api-ssl
/ip service set api-ssl port=8729

# 3. Configurare utilizator dedicat pentru SchoolSec
/user add name=schoolsec password=parola-puternica group=read
# Sau full pentru auto-blocare IP:
/user add name=schoolsec password=parola-puternica group=full

# 4. Activare streaming TZSP
/tool sniffer
set filter-interface=bridge-lan \
    streaming-enabled=yes \
    streaming-server=192.168.88.X \
    filter-stream=yes
/tool sniffer start

# 5. (Opțional) Firewall logging pentru detectare atacuri externe
/ip firewall filter add chain=input action=drop \
    src-address-list=!whitelist log=yes log-prefix="FW-DROP:" \
    comment="Log și drop conexiuni neautorizate"
```

### Timeline sincronizare (cum funcționează periodic)

```
T+0s    Server pornit → conectare API MikroTik
T+5s    Prima sincronizare DHCP → descoperire dispozitive și VLAN-uri
T+10s   Pornire TZSP listener → recepție trafic în timp real
T+60s   Sincronizare periodică: DHCP, conexiuni active, statistici interfețe
T+60s   Analiză loguri firewall → detectare atacuri externe
...
T+N*60s Sincronizare continuă cu intervalul MIKROTIK_SYNC_INTERVAL
```

---

## 🔍 Funcționalități

### 1. Monitorizare Trafic

- Captură pachete în timp real (TCP, UDP, ICMP, HTTP, HTTPS, DNS, ARP)
- Statistici live: total pachete, volume de date, top surse
- Grafic interactiv cu distribuția protocoalelor
- Tabel cu ultimele pachete capturate

### 2. Detectare Intruziuni (IDS)

| Tip Amenințare | Descriere | Severitate |
|---------------|-----------|------------|
| **Port Scan** | Un IP accesează >15 porturi în 10 secunde | High |
| **Brute Force** | >10 conexiuni la SSH/RDP/FTP în 30 secunde | High |
| **Trafic Anormal** | Un IP transmite >10 MB în 60 secunde | Medium |
| **ARP Sweep** | >20 cereri ARP în 5 secunde | Critical |

### 3. Gestionare Utilizatori

**Roluri disponibile:**

| Rol | Permisiuni |
|-----|-----------|
| **Admin** | Toate funcționalitățile, gestionare utilizatori, blocare IP-uri |
| **Monitor** | Vizualizare trafic, alerte și loguri (doar citire) |

### 4. Dashboard Web

- Statistici live actualizate automat la 5 secunde
- Grafic interactiv protocoale (Chart.js)
- Top 10 surse de trafic
- Alerte recente și trafic recent

### 5. Loguri de Securitate

- Înregistrare automată a tuturor evenimentelor
- Filtrare după severitate, tip eveniment, IP
- Export CSV cu filtre aplicate
- Severități: `info`, `warning`, `error`, `critical`

---

## 🛡️ Arhitectura Securității

```
Internet/Rețea școlii
        │
        ▼
┌───────────────────┐
│   Scapy Sniffer   │  ← Captură pachete în timp real
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  IDS Detector     │  ← Analiză comportament (port scan, brute force)
└────────┬──────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌────────┐
│Alerte │ │  Log   │  ← Stocare în SQLite
└───┬───┘ └────────┘
    │
    ▼
┌───────────────────┐
│  Flask Dashboard  │  ← Interfața web pentru administratori
└───────────────────┘
```

---

## 📚 Utilizare pentru Elevi

Acest proiect demonstrează:

1. **Flask** - Framework web Python
2. **SQLAlchemy** - ORM pentru baze de date
3. **Flask-Login** - Autentificare și sesiuni
4. **Scapy** - Captură și analiză pachete de rețea
5. **Bootstrap 5** - Interfață responsive modernă
6. **Chart.js** - Vizualizare date în timp real
7. **Design Pattern**: Application Factory, Blueprint, Observer

---

## ⚠️ Note Importante

- Aplicația este destinată **exclusiv uzului educațional**
- Capturarea pachetelor necesită privilegii de administrator (Linux/Mac)
- Pe Windows, folosiți modul simulat (`SIMULATION_MODE=true`)
- Nu utilizați în rețele de producție fără configurare suplimentară de securitate

---

## 📄 Licență

Proiect educațional - Uz liber în scop academic.
