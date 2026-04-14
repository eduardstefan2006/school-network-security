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
    # Scorul de anomalie ML (0-100); None dacă alerta este generată de reguli statice
    anomaly_score = db.Column(db.Float, nullable=True)
    # Nivelul de încredere al modelului ML (0-1)
    model_confidence = db.Column(db.Float, nullable=True)
    # True dacă alerta a fost generată de ML, False dacă de regulile statice
    is_ml_generated = db.Column(db.Boolean, default=False, nullable=False)

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
            'is_blocked': self.is_blocked,
            'anomaly_score': self.anomaly_score,
            'model_confidence': self.model_confidence,
            'is_ml_generated': self.is_ml_generated,
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
    # ID-ul utilizatorului care a generat evenimentul (nullable pentru evenimente de sistem)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
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
# Model Hostname Blocat
# =============================================================================
class BlockedHostname(db.Model):
    """Model pentru hostname-urile blocate în sistem (dispozitive cu MAC randomizat)."""
    __tablename__ = 'blocked_hostnames'

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), unique=True, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    blocked_by = db.Column(db.String(80), default='system', nullable=False)
    blocked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    # IP-ul și MAC-ul asociate la momentul blocării (informativ)
    associated_ip = db.Column(db.String(45), nullable=True)
    associated_mac = db.Column(db.String(17), nullable=True)
    # DHCP server name pe care a fost văzut (ex: Sala2Parter)
    dhcp_server = db.Column(db.String(100), nullable=True)

    def to_dict(self):
        """Convertește hostname-ul blocat în dicționar."""
        return {
            'id': self.id,
            'hostname': self.hostname,
            'reason': self.reason,
            'blocked_by': self.blocked_by,
            'blocked_at': self.blocked_at.strftime('%Y-%m-%d %H:%M:%S'),
            'is_active': self.is_active,
            'associated_ip': self.associated_ip,
            'associated_mac': self.associated_mac,
            'dhcp_server': self.dhcp_server,
        }

    def __repr__(self):
        return f'<BlockedHostname {self.hostname}>'


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
    # True dacă tipul a fost setat manual de admin — blochează reclasificarea automată
    type_locked = db.Column(db.Boolean, default=False)

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
# Model Trafic Aplicații / Site-uri (agregare zilnică)
# =============================================================================
class AppTrafficStat(db.Model):
    """Agregare zilnică per IP sursă și aplicație/site accesat."""
    __tablename__ = 'app_traffic_stats'

    id = db.Column(db.Integer, primary_key=True)
    stat_date = db.Column(db.Date, nullable=False, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    hostname = db.Column(db.String(255), nullable=False, index=True)
    app_name = db.Column(db.String(100), nullable=True, index=True)
    bytes_total = db.Column(db.BigInteger, default=0)
    packets_count = db.Column(db.Integer, default=0)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        db.UniqueConstraint('stat_date', 'source_ip', 'hostname', name='uq_app_traffic_stat'),
    )

    def __repr__(self):
        return f'<AppTrafficStat {self.stat_date} {self.source_ip} -> {self.hostname}>'


# =============================================================================
# Model Configurație MikroTik
# =============================================================================
class MikroTikConfig(db.Model):
    """Configurație MikroTik stocată securizat în baza de date.

    Parola este criptată cu Fernet (cheie derivată din SECRET_KEY).
    Tabelul conține întotdeauna cel mult un rând (id=1).
    """
    __tablename__ = 'mikrotik_config'

    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(255), nullable=False, default='')
    port = db.Column(db.Integer, nullable=False, default=8728)
    username = db.Column(db.String(255), nullable=False, default='admin')
    # Parola criptată cu Fernet; None înseamnă „nesetată"
    password_encrypted = db.Column(db.Text, nullable=True)
    enabled = db.Column(db.Boolean, default=False, nullable=False)
    # Câmpuri de audit
    updated_by = db.Column(db.String(80), nullable=True)
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self):
        return f'<MikroTikConfig host={self.host} enabled={self.enabled}>'


# =============================================================================
# Model Configurație Rețea (stare setup + setări generale)
# =============================================================================
class NetworkConfig(db.Model):
    """Tabel cheie-valoare pentru configurația globală a sistemului.

    Folosit pentru a stoca starea setup-ului (setup_complete=true/false)
    și alte setări persistente independente de MikroTik.
    """
    __tablename__ = 'network_config'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self):
        return f'<NetworkConfig {self.key}={self.value}>'


# =============================================================================
# Model VLAN Descoperit
# =============================================================================
class DiscoveredVLAN(db.Model):
    """VLAN-uri descoperite automat prin auto-discovery (din RouterOS).

    Înlocuiește maparea statică hardcodată din sniffer.py cu date din baza de date,
    permițând funcționarea pe orice rețea fără configurare manuală.
    """
    __tablename__ = 'discovered_vlans'

    id = db.Column(db.Integer, primary_key=True)
    vlan_id = db.Column(db.Integer, nullable=False)
    subnet = db.Column(db.String(50), nullable=True)    # ex: '192.168.221.0/28'
    name = db.Column(db.String(100), nullable=True)     # ex: 'Sala1Parter'
    interface = db.Column(db.String(100), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    discovered_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'vlan_id': self.vlan_id,
            'subnet': self.subnet,
            'name': self.name,
            'interface': self.interface,
            'is_active': self.is_active,
        }

    def __repr__(self):
        return f'<DiscoveredVLAN vlan_id={self.vlan_id} subnet={self.subnet}>'


# =============================================================================
# Model Log Firewall (syslog de la RouterOS)
# =============================================================================
class FirewallLog(db.Model):
    """Intrări de log firewall primite prin syslog UDP de la RouterOS.

    Mesajele cu prefix SCHOOLSEC-DROP-* sau SCHOOLSEC-REJECT-* sunt
    parsate și stocate aici de serverul syslog intern.
    """
    __tablename__ = 'firewall_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    # Adresa IP sursă
    src_ip = db.Column(db.String(45), nullable=True)
    # Adresa IP destinație
    dst_ip = db.Column(db.String(45), nullable=True)
    # Portul sursă
    src_port = db.Column(db.Integer, nullable=True)
    # Portul destinație
    dst_port = db.Column(db.Integer, nullable=True)
    # Protocolul (TCP, UDP, ICMP, etc.)
    protocol = db.Column(db.String(20), nullable=True)
    # Acțiunea: drop, reject
    action = db.Column(db.String(20), nullable=True)
    # Mesajul brut primit prin syslog
    raw_message = db.Column(db.Text, nullable=True)

    def to_dict(self):
        """Convertește log-ul în dicționar pentru API JSON."""
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'action': self.action,
            'raw_message': self.raw_message,
        }

    def __repr__(self):
        return f'<FirewallLog {self.action} {self.src_ip}->{self.dst_ip} at {self.timestamp}>'


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


# =============================================================================
# Model Date Antrenare ML
# =============================================================================
class MLTrainingData(db.Model):
    """Date de antrenare pentru modelele ML de detectare a anomaliilor.

    Stochează vectorii de caracteristici extrase periodic per IP sursă,
    utilizați pentru antrenarea modelelor Isolation Forest și LOF.
    """
    __tablename__ = 'ml_training_data'

    id = db.Column(db.Integer, primary_key=True)
    # Timestamp-ul colectării
    timestamp = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    # IP-ul sursă monitorizat
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    # Vectorul de caracteristici serializat ca JSON
    feature_vector = db.Column(db.Text, nullable=False)
    # Etichetă: True = trafic de atac (setat de admin sau de regulile IDS)
    is_attack = db.Column(db.Boolean, default=False, nullable=False)
    # Predicția modelului (scor de anomalie 0-100, null dacă nu a fost evaluat)
    model_prediction = db.Column(db.Float, nullable=True)
    # Nivelul de încredere al predicției (0-1)
    confidence = db.Column(db.Float, nullable=True)
    # Data creării (pentru curățare periodică)
    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def to_dict(self):
        """Convertește înregistrarea în dicționar pentru API JSON."""
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'source_ip': self.source_ip,
            'is_attack': self.is_attack,
            'model_prediction': self.model_prediction,
            'confidence': self.confidence,
        }

    def __repr__(self):
        return f'<MLTrainingData {self.source_ip} at {self.timestamp}>'


# =============================================================================
# Modele Faza 3: Autonomous Response Agent
# =============================================================================

class ResponseFeedback(db.Model):
    """Feedback al administratorilor pentru răspunsurile automate ale sistemului."""
    __tablename__ = 'response_feedback'

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id'), nullable=False)
    # confirmed | false_positive | partial
    feedback_type = db.Column(db.String(20), nullable=False)
    comment = db.Column(db.Text, nullable=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    alert = db.relationship('Alert', backref='feedbacks', lazy=True)
    admin = db.relationship('User', backref='feedbacks', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'feedback_type': self.feedback_type,
            'comment': self.comment,
            'admin_id': self.admin_id,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        }

    def __repr__(self):
        return f'<ResponseFeedback alert={self.alert_id} type={self.feedback_type}>'


class ResponseAction(db.Model):
    """Audit trail pentru toate acțiunile de răspuns automat."""
    __tablename__ = 'response_actions'

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id'), nullable=True)
    source_ip = db.Column(db.String(45), nullable=False)
    # block_ip | block_mac | block_hostname
    action_type = db.Column(db.String(50), nullable=False)
    # IP, MAC sau hostname blocat
    target = db.Column(db.String(255), nullable=True)
    # low | medium | high | critical
    severity_level = db.Column(db.String(20), nullable=False)
    anomaly_score = db.Column(db.Float, nullable=False)
    # active | reverted | expired
    status = db.Column(db.String(20), default='active', nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    # Momentul la care blocarea expiră automat
    expires_at = db.Column(db.DateTime, nullable=True)

    alert = db.relationship('Alert', backref='response_actions', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'source_ip': self.source_ip,
            'action_type': self.action_type,
            'target': self.target,
            'severity_level': self.severity_level,
            'anomaly_score': self.anomaly_score,
            'status': self.status,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'expires_at': self.expires_at.strftime('%Y-%m-%d %H:%M:%S') if self.expires_at else None,
        }

    def __repr__(self):
        return f'<ResponseAction {self.action_type} {self.target} [{self.status}]>'


class IncidentTicket(db.Model):
    """Tickete de incident create automat pentru amenințările critice."""
    __tablename__ = 'incident_tickets'

    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(45), nullable=False)
    threat_type = db.Column(db.String(100), nullable=False)
    # low | medium | high | critical
    severity = db.Column(db.String(20), nullable=False)
    anomaly_score = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    # open | investigating | resolved
    status = db.Column(db.String(20), default='open', nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    resolved_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'source_ip': self.source_ip,
            'threat_type': self.threat_type,
            'severity': self.severity,
            'anomaly_score': self.anomaly_score,
            'description': self.description,
            'status': self.status,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'resolved_at': self.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if self.resolved_at else None,
        }

    def __repr__(self):
        return f'<IncidentTicket {self.source_ip} [{self.status}]>'
