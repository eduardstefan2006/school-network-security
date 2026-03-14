"""
Modelele bazei de date pentru sistemul de securitate.
Folosim SQLAlchemy ORM pentru a defini structura datelor.
"""
from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager


# =============================================================================
# Model Utilizator
# =============================================================================
class User(UserMixin, db.Model):
    """Model pentru utilizatorii sistemului."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    # Roluri: 'admin' sau 'monitor'
    role = db.Column(db.String(20), default='monitor', nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        """Generează hash-ul parolei."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifică dacă parola este corectă."""
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        """Verifică dacă utilizatorul are rol de admin."""
        return self.role == 'admin'

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


@login_manager.user_loader
def load_user(user_id):
    """Funcție callback pentru Flask-Login - încarcă utilizatorul din baza de date."""
    return db.session.get(User, int(user_id))


# =============================================================================
# Model Alertă
# =============================================================================
class Alert(db.Model):
    """Model pentru alertele de securitate detectate."""
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    # Tipul alertei: port_scan, brute_force, high_traffic, etc.
    alert_type = db.Column(db.String(50), nullable=False)
    # IP-ul sursă suspect
    source_ip = db.Column(db.String(45), nullable=False)
    # IP-ul destinație (opțional)
    destination_ip = db.Column(db.String(45), nullable=True)
    # Portul țintă (opțional)
    port = db.Column(db.Integer, nullable=True)
    # Mesajul descriptiv
    message = db.Column(db.Text, nullable=False)
    # Severitatea: low, medium, high, critical
    severity = db.Column(db.String(20), default='medium', nullable=False)
    # Starea: active, resolved, dismissed
    status = db.Column(db.String(20), default='active', nullable=False)
    # Timestamp-ul alertei
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    # IP-ul a fost blocat?
    is_blocked = db.Column(db.Boolean, default=False)

    def to_dict(self):
        """Convertește alerta în dicționar pentru API JSON."""
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'port': self.port,
            'message': self.message,
            'severity': self.severity,
            'status': self.status,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'is_blocked': self.is_blocked
        }

    def __repr__(self):
        return f'<Alert {self.alert_type} from {self.source_ip}>'


# =============================================================================
# Model Log de Securitate
# =============================================================================
class SecurityLog(db.Model):
    """Model pentru logurile de securitate ale sistemului."""
    __tablename__ = 'security_logs'

    id = db.Column(db.Integer, primary_key=True)
    # Tipul evenimentului: packet_captured, alert_generated, user_login, etc.
    event_type = db.Column(db.String(50), nullable=False)
    # IP-ul sursă
    source_ip = db.Column(db.String(45), nullable=True)
    # IP-ul destinație
    destination_ip = db.Column(db.String(45), nullable=True)
    # Protocolul (TCP, UDP, ICMP, etc.)
    protocol = db.Column(db.String(20), nullable=True)
    # Portul
    port = db.Column(db.Integer, nullable=True)
    # Mesajul descriptiv
    message = db.Column(db.Text, nullable=False)
    # Severitatea: info, warning, error, critical
    severity = db.Column(db.String(20), default='info', nullable=False)
    # Timestamp-ul
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    # Date adiționale (JSON ca string)
    extra_data = db.Column(db.Text, nullable=True)

    def to_dict(self):
        """Convertește log-ul în dicționar pentru export CSV/JSON."""
        return {
            'id': self.id,
            'event_type': self.event_type,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'protocol': self.protocol,
            'port': self.port,
            'message': self.message,
            'severity': self.severity,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'extra_data': self.extra_data
        }

    def __repr__(self):
        return f'<Log {self.event_type} at {self.timestamp}>'


# =============================================================================
# Model IP Blocat
# =============================================================================
class BlockedIP(db.Model):
    """Model pentru IP-urile blocate în sistem."""
    __tablename__ = 'blocked_ips'

    id = db.Column(db.Integer, primary_key=True)
    # Adresa IP blocată
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    # Motivul blocării
    reason = db.Column(db.Text, nullable=False)
    # Cine a blocat IP-ul (utilizator sau sistem automat)
    blocked_by = db.Column(db.String(80), default='system', nullable=False)
    # Timestamp-ul blocării
    blocked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    # Este activ blocarea?
    is_active = db.Column(db.Boolean, default=True)

    def to_dict(self):
        """Convertește IP-ul blocat în dicționar."""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reason': self.reason,
            'blocked_by': self.blocked_by,
            'blocked_at': self.blocked_at.strftime('%Y-%m-%d %H:%M:%S'),
            'is_active': self.is_active
        }

    def __repr__(self):
        return f'<BlockedIP {self.ip_address}>'


# =============================================================================
# Model MAC Blocat
# =============================================================================
class BlockedMAC(db.Model):
    """Model pentru MAC-urile blocate în sistem."""
    __tablename__ = 'blocked_macs'

    id = db.Column(db.Integer, primary_key=True)
    # Adresa MAC blocată (format AA:BB:CC:DD:EE:FF)
    mac_address = db.Column(db.String(17), unique=True, nullable=False)
    # Motivul blocării
    reason = db.Column(db.Text, nullable=False)
    # Cine a blocat (utilizator sau sistem automat)
    blocked_by = db.Column(db.String(80), default='system', nullable=False)
    # Timestamp-ul blocării
    blocked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    # Este activă blocarea?
    is_active = db.Column(db.Boolean, default=True)
    # IP-ul asociat la momentul blocării (informativ)
    associated_ip = db.Column(db.String(45), nullable=True)

    def to_dict(self):
        """Convertește MAC-ul blocat în dicționar."""
        return {
            'id': self.id,
            'mac_address': self.mac_address,
            'reason': self.reason,
            'blocked_by': self.blocked_by,
            'blocked_at': self.blocked_at.strftime('%Y-%m-%d %H:%M:%S'),
            'is_active': self.is_active,
            'associated_ip': self.associated_ip,
        }

    def __repr__(self):
        return f'<BlockedMAC {self.mac_address}>'


# =============================================================================
# Model Dispozitiv Rețea
# =============================================================================
class NetworkDevice(db.Model):
    """Model pentru dispozitivele detectate în rețea."""
    __tablename__ = 'network_devices'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    mac_address = db.Column(db.String(17), nullable=True)
    hostname = db.Column(db.String(255), nullable=True)
    # Tipul dispozitivului: router, switch, ap, camera, server, client, mobile, unknown
    device_type = db.Column(db.String(50), default='unknown')
    description = db.Column(db.String(255), nullable=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    total_packets = db.Column(db.Integer, default=0)
    total_bytes = db.Column(db.BigInteger, default=0)
    # True pentru dispozitivele cunoscute (din whitelist / infrastructură)
    is_known = db.Column(db.Boolean, default=False)
    is_online = db.Column(db.Boolean, default=True)
    vlan = db.Column(db.String(20), nullable=True)
    alert_count = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<NetworkDevice {self.ip_address} ({self.device_type})>'


# =============================================================================
# Model Conexiuni per IP
# =============================================================================
class IPConnection(db.Model):
    """Conexiuni detectate per IP sursă — hostname-uri accesate și consum bandă."""
    __tablename__ = 'ip_connections'

    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    hostname = db.Column(db.String(255), nullable=False)   # ex: facebook.com, tiktok.com
    app_name = db.Column(db.String(100), nullable=True)    # ex: Facebook, TikTok, WhatsApp
    bytes_total = db.Column(db.BigInteger, default=0)
    packets_count = db.Column(db.Integer, default=0)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('source_ip', 'hostname', name='uq_ip_hostname'),)

    def __repr__(self):
        return f'<IPConnection {self.source_ip} -> {self.hostname}>'


# =============================================================================
# Model Statistici Pachete
# =============================================================================
class PacketStat(db.Model):
    """Model pentru statisticile pachetelor capturate."""
    __tablename__ = 'packet_stats'

    id = db.Column(db.Integer, primary_key=True)
    # Protocolul
    protocol = db.Column(db.String(20), nullable=False)
    # Numărul de pachete
    count = db.Column(db.Integer, default=0)
    # Volumul de date în bytes
    bytes_total = db.Column(db.BigInteger, default=0)
    # Data statisticii (pe oră)
    hour = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f'<PacketStat {self.protocol}: {self.count} packets>'
