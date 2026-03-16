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

**TZSP** (TaZmen Sniffer Protocol) este un protocol care permite unui router MikroTik să trimită o copie a traficului de rețea (mirroring) către un server extern prin UDP. SchoolSec poate primi și analiza acest trafic fără a fi necesar acces direct la interfața de rețea.

### Configurare MikroTik

Pe routerul MikroTik (RouterOS), activați streaming-ul TZSP:

```routeros
/tool sniffer
set filter-interface=RETEA \
    streaming-enabled=yes \
    streaming-server=192.168.2.243 \
    filter-stream=yes
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
