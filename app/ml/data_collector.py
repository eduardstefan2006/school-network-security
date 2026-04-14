"""
Colectarea datelor pentru antrenarea modelelor ML.

Menține un buffer rolling per IP (ultimul minut de pachete) și salvează
periodic vectorii de caracteristici în tabelul MLTrainingData.
"""
import json
import logging
import threading
import time
from collections import defaultdict, deque

from app.ml.features import extract_features, features_to_vector

logger = logging.getLogger(__name__)

# Fereastra de timp pentru buffer-ul rolling (secunde)
_BUFFER_WINDOW = 60

# Intervalul de salvare a caracteristicilor în baza de date (secunde)
_SAVE_INTERVAL = 60

# Numărul maxim de pachete păstrate în buffer per IP
_MAX_BUFFER_SIZE = 1000


class DataCollector:
    """Colectează pachete per IP și extrage caracteristici ML.

    Buffer rolling: păstrează ultimele ``_BUFFER_WINDOW`` secunde de pachete
    per IP sursă. La fiecare ``_SAVE_INTERVAL`` secunde, extrage caracteristicile
    și le salvează în baza de date pentru antrenare ulterioară.

    Thread-safe.
    """

    def __init__(self):
        self._lock = threading.RLock()
        # ip -> deque de dict-uri pachet
        self._buffers: dict = defaultdict(lambda: deque(maxlen=_MAX_BUFFER_SIZE))
        self._last_save = time.time()
        # ip -> ultimele caracteristici extrase
        self._last_features: dict = {}

    def add_packet(self, packet_info: dict) -> None:
        """Adaugă un pachet în buffer-ul IP-ului sursă.

        Args:
            packet_info: Dicționar cu detalii pachet (src_ip, protocol, dst_port,
                         dst_ip, size, is_tcp_syn, is_tcp_ack, dns_query, is_failed).
        """
        src_ip = packet_info.get('src_ip', '')
        if not src_ip:
            return

        entry = {
            'timestamp': packet_info.get('timestamp', time.time()),
            'protocol': packet_info.get('protocol', 'UNKNOWN'),
            'dst_port': packet_info.get('dst_port'),
            'dst_ip': packet_info.get('dst_ip', ''),
            'size': packet_info.get('size', 0),
            'is_tcp_syn': packet_info.get('is_tcp_syn', False),
            'is_tcp_ack': packet_info.get('is_tcp_ack', False),
            'dns_query': packet_info.get('dns_query'),
            'is_failed': packet_info.get('is_failed', False),
        }

        with self._lock:
            self._buffers[src_ip].append(entry)

    def get_features(self, ip: str) -> dict:
        """Extrage caracteristicile curente pentru un IP.

        Args:
            ip: Adresa IP sursă.

        Returns:
            Dicționar cu vectorul de caracteristici.
        """
        with self._lock:
            buffer_list = list(self._buffers.get(ip, []))

        return extract_features(buffer_list, window_seconds=_BUFFER_WINDOW)

    def get_all_active_ips(self) -> list:
        """Returnează lista IP-urilor cu activitate recentă."""
        cutoff = time.time() - _BUFFER_WINDOW
        with self._lock:
            active = []
            for ip, buf in self._buffers.items():
                if buf and buf[-1].get('timestamp', 0) >= cutoff:
                    active.append(ip)
            return active

    def get_feature_vectors_for_training(self) -> list:
        """Extrage vectorii de caracteristici pentru toate IP-urile active.

        Returns:
            Listă de vectori de caracteristici (liste de float-uri).
        """
        vectors = []
        for ip in self.get_all_active_ips():
            features = self.get_features(ip)
            vec = features_to_vector(features)
            vectors.append(vec)
        return vectors

    def maybe_save_to_db(self, app, is_attack_map: dict = None) -> None:
        """Salvează caracteristicile în baza de date dacă a trecut intervalul.

        Args:
            app: Instanța Flask (necesară pentru context aplicație).
            is_attack_map: Dicționar ip -> bool — etichete de atac (opțional).
        """
        now = time.time()
        if now - self._last_save < _SAVE_INTERVAL:
            return

        self._last_save = now

        try:
            with app.app_context():
                self._flush_to_db(app, is_attack_map or {})
        except Exception as exc:
            logger.error("[ML DataCollector] Eroare la salvarea în BD: %s", exc)

    def _flush_to_db(self, app, is_attack_map: dict) -> None:
        """Salvează efectiv caracteristicile în baza de date."""
        from app import db
        from app.models import MLTrainingData

        active_ips = self.get_all_active_ips()
        if not active_ips:
            return

        saved = 0
        for ip in active_ips:
            features = self.get_features(ip)
            # Optimizare: dacă nu există pachete, toate valorile sunt 0 — sărim
            if features.get('packets_per_minute', 0) == 0:
                continue

            entry = MLTrainingData(
                source_ip=ip,
                feature_vector=json.dumps(features),
                is_attack=is_attack_map.get(ip, False),
            )
            db.session.add(entry)
            saved += 1

        if saved > 0:
            try:
                db.session.commit()
                logger.debug("[ML DataCollector] Salvat %d vectori de caracteristici.", saved)
            except Exception as exc:
                db.session.rollback()
                logger.error("[ML DataCollector] Eroare commit BD: %s", exc)

    def cleanup_old_buffers(self) -> None:
        """Elimină buffer-ele IP-urilor inactive (fără pachete în ultimul minut)."""
        cutoff = time.time() - _BUFFER_WINDOW * 2
        with self._lock:
            inactive = [
                ip for ip, buf in self._buffers.items()
                if not buf or buf[-1].get('timestamp', 0) < cutoff
            ]
            for ip in inactive:
                del self._buffers[ip]


# Instanța globală a colectorului de date
data_collector = DataCollector()
