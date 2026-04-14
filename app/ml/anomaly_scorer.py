"""
Scorer de anomalii — combină scorurile din toate modelele ML disponibile.

Scara de scoruri (0-100):
  0-20:  Normal
  20-40: Ușor anormal
  40-60: Suspect
  60-80: Înalt suspect
  80-100: Anomalie critică
"""
import logging
import time
from collections import defaultdict, deque

from app.ml.features import extract_features, features_to_vector

logger = logging.getLogger(__name__)

# Valoare mică pentru evitarea împărțirii la zero în calculele statistice
_EPSILON = 1e-6

# Ponderile modelelor în scorul final
_WEIGHT_ISOLATION_FOREST = 0.5
_WEIGHT_LOF = 0.4
_WEIGHT_STATISTICAL = 0.1

# Fereastra de timp pentru baseline statistic (secunde)
_BASELINE_WINDOW = 3600  # 1 oră

# Numărul maxim de valori păstrate în istoricul scorurilor per IP
_SCORE_HISTORY_MAXLEN = 1440  # ~24h la câte un scor/minut


class AnomalyScorer:
    """Calculează scoruri de anomalie combinând mai multe modele ML.

    Utilizare:
        scorer = AnomalyScorer()
        score, confidence = scorer.score_ip(ip, data_collector, anomaly_models)
    """

    def __init__(self):
        # ip -> deque de (timestamp, score) pentru tendințe
        self._score_history: dict = defaultdict(lambda: deque(maxlen=_SCORE_HISTORY_MAXLEN))
        # ip -> deque de valori bytes_per_minute pentru baseline statistic
        self._baseline_bytes: dict = defaultdict(lambda: deque(maxlen=60))
        self._baseline_packets: dict = defaultdict(lambda: deque(maxlen=60))

    def score_ip(self, ip: str, data_collector, anomaly_models) -> tuple:
        """Calculează scorul de anomalie pentru un IP.

        Args:
            ip: Adresa IP de evaluat.
            data_collector: Instanța DataCollector cu buffer-ul curent.
            anomaly_models: Instanța AnomalyModels cu modelele antrenate.

        Returns:
            Tuple (anomaly_score: float 0-100, confidence: float 0-1)
        """
        features = data_collector.get_features(ip)
        vec = features_to_vector(features)

        # Dacă nu există trafic, scorul este 0
        if features.get('packets_per_minute', 0) == 0:
            return 0.0, 0.0

        scores = []
        weights = []

        # Scor Isolation Forest + LOF (dacă modelele sunt antrenate)
        if anomaly_models.is_trained:
            model_scores = anomaly_models.score(vec)
            if model_scores.get('available'):
                if_score = model_scores['isolation_forest_score']
                lof_score = model_scores['lof_score']
                scores.append(if_score * _WEIGHT_ISOLATION_FOREST)
                weights.append(_WEIGHT_ISOLATION_FOREST)
                scores.append(lof_score * _WEIGHT_LOF)
                weights.append(_WEIGHT_LOF)

        # Scor statistic bazat pe baseline (funcționează fără antrenare ML)
        stat_score = self._statistical_score(ip, features)
        scores.append(stat_score * _WEIGHT_STATISTICAL)
        weights.append(_WEIGHT_STATISTICAL)

        if not weights:
            return 0.0, 0.0

        total_weight = sum(weights)
        combined = sum(scores) / total_weight if total_weight > 0 else 0.0

        # Scalăm la 0-100
        anomaly_score = min(100.0, max(0.0, combined * 100.0))

        # Confidence: mai mare dacă modelele ML sunt disponibile și antrenate.
        # 0.9 = ambele modele (IF + LOF) sunt active → încredere ridicată
        # 0.4 = doar baseline statistic → încredere scăzută (fără suficiente date de antrenare)
        confidence = 0.9 if anomaly_models.is_trained else 0.4

        # Salvăm în istoricul scorurilor
        self._score_history[ip].append((time.time(), anomaly_score))

        # Actualizăm baseline
        self._baseline_bytes[ip].append(features.get('bytes_per_minute', 0))
        self._baseline_packets[ip].append(features.get('packets_per_minute', 0))

        return anomaly_score, confidence

    def _statistical_score(self, ip: str, features: dict) -> float:
        """Calculează un scor statistic simplu bazat pe deviația față de baseline.

        Compară valorile curente cu media și deviația standard din istoricul recent.

        Returns:
            Float 0-1.
        """
        bytes_history = list(self._baseline_bytes.get(ip, []))
        packets_history = list(self._baseline_packets.get(ip, []))

        if len(bytes_history) < 3:
            # Insuficiente date de baseline — returnăm un scor neutru mic
            return 0.1

        # Calculăm z-score pentru bytes per minute
        mean_bytes = sum(bytes_history) / len(bytes_history)
        std_bytes = (
            (sum((x - mean_bytes) ** 2 for x in bytes_history) / len(bytes_history)) ** 0.5
        )

        current_bytes = features.get('bytes_per_minute', 0)
        z_bytes = abs(current_bytes - mean_bytes) / (std_bytes + _EPSILON)

        # Calculăm z-score pentru packets per minute
        mean_pkts = sum(packets_history) / len(packets_history)
        std_pkts = (
            (sum((x - mean_pkts) ** 2 for x in packets_history) / len(packets_history)) ** 0.5
        )

        current_pkts = features.get('packets_per_minute', 0)
        z_pkts = abs(current_pkts - mean_pkts) / (std_pkts + _EPSILON)

        # Combinăm z-score-urile și normalizăm la [0, 1]
        # Un z-score > 3 este considerat outlier semnificativ
        combined_z = (z_bytes + z_pkts) / 2.0
        score = min(1.0, combined_z / 3.0)

        return score

    def get_score_history(self, ip: str, limit: int = 60) -> list:
        """Returnează istoricul scorurilor pentru un IP.

        Returns:
            Listă de tuple (timestamp, score).
        """
        history = list(self._score_history.get(ip, []))
        return history[-limit:]

    def get_top_anomalies(self, n: int = 20) -> list:
        """Returnează top-N IP-uri după scorul de anomalie curent.

        Returns:
            Listă sortată descrescător de dict-uri {ip, score, last_seen}.
        """
        result = []
        now = time.time()
        for ip, history in self._score_history.items():
            if not history:
                continue
            last_ts, last_score = history[-1]
            # Includem doar scoruri recente (ultimele 5 minute)
            if now - last_ts > 300:
                continue
            result.append({
                'ip': ip,
                'score': round(last_score, 1),
                'last_seen': last_ts,
            })

        result.sort(key=lambda x: x['score'], reverse=True)
        return result[:n]

    @staticmethod
    def score_label(score: float) -> str:
        """Returnează eticheta textuală a unui scor de anomalie."""
        if score < 20:
            return 'Normal'
        elif score < 40:
            return 'Ușor anormal'
        elif score < 60:
            return 'Suspect'
        elif score < 80:
            return 'Înalt suspect'
        else:
            return 'Anomalie critică'

    @staticmethod
    def score_severity(score: float) -> str:
        """Returnează severitatea corespunzătoare scorului (pentru alerte IDS)."""
        if score < 40:
            return 'low'
        elif score < 60:
            return 'medium'
        elif score < 80:
            return 'high'
        else:
            return 'critical'


# Instanța globală a scorer-ului
anomaly_scorer = AnomalyScorer()
