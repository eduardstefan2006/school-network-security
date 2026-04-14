"""
Modele ML pentru detectarea anomaliilor în traficul de rețea.

Implementează:
- Model A: Isolation Forest (detectare outlieri statistici)
- Model B: Local Outlier Factor (detectare outlieri pe densitate locală)

Ambele modele sunt nesupervizate și funcționează imediat, fără date de antrenare
etichetate. Se adaptează la traficul normal al rețelei școlare.
"""
import logging
import threading

logger = logging.getLogger(__name__)

# Numărul minim de puncte de date necesare pentru antrenarea modelelor
MIN_SAMPLES_FOR_TRAINING = 10

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False
    logger.warning(
        "[ML] scikit-learn nu este instalat. Modelele ML vor fi dezactivate. "
        "Instalați cu: pip install scikit-learn"
    )


class AnomalyModels:
    """Containerul modelelor ML de detectare a anomaliilor.

    Gestionează Isolation Forest și Local Outlier Factor.
    Thread-safe prin utilizarea unui RLock.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._scaler = None
        self._isolation_forest = None
        self._lof = None
        self._is_trained = False
        self._training_samples = 0
        # Calibrare IF: statisticile decision_function pe datele de antrenare
        self._if_decision_mean = 0.0
        self._if_decision_std = 1.0
        # Calibrare LOF: statisticile decision_function pe datele de antrenare
        self._lof_decision_mean = 0.0
        self._lof_decision_std = 1.0

    @property
    def is_trained(self) -> bool:
        """Returnează True dacă modelele au fost antrenate."""
        with self._lock:
            return self._is_trained

    @property
    def training_samples(self) -> int:
        """Numărul de eșantioane folosite la ultima antrenare."""
        with self._lock:
            return self._training_samples

    @property
    def sklearn_available(self) -> bool:
        """Returnează True dacă scikit-learn este disponibil."""
        return _SKLEARN_AVAILABLE

    def train(self, feature_vectors: list) -> bool:
        """Antrenează (sau reantrenează) modelele cu vectorii de caracteristici furnizați.

        Args:
            feature_vectors: Listă de liste cu valori float (vectori de caracteristici).

        Returns:
            True dacă antrenarea a reușit, False altfel.
        """
        if not _SKLEARN_AVAILABLE:
            return False

        if len(feature_vectors) < MIN_SAMPLES_FOR_TRAINING:
            logger.info(
                "[ML] Insuficiente eșantioane pentru antrenare: %d < %d",
                len(feature_vectors), MIN_SAMPLES_FOR_TRAINING,
            )
            return False

        try:
            import numpy as np

            X = np.array(feature_vectors, dtype=float)

            # Normalizăm datele
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            # Isolation Forest
            # contamination=0.1: Estimăm că ~10% din traficul colectat poate fi anormal.
            # Această valoare este fixată la 0.1 (nu este configurabilă).
            # O valoare mai mică → mai puțini falși pozitivi, dar mai multe anomalii ratate.
            iso_forest = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42,
                n_jobs=-1,
            )
            iso_forest.fit(X_scaled)

            # Calibrare: calculăm statistica scorurilor pe datele de antrenare
            # pentru a normaliza corect scorurile pe date noi.
            train_decisions = iso_forest.decision_function(X_scaled)
            if_decision_mean = float(train_decisions.mean())
            if_decision_std = float(train_decisions.std()) + 1e-6

            # LOF — folosim n_neighbors adaptat la numărul de eșantioane
            n_neighbors = min(20, max(2, len(feature_vectors) // 5))
            lof = LocalOutlierFactor(
                n_neighbors=n_neighbors,
                novelty=True,  # Permite predicții pe date noi
                contamination=0.1,
                n_jobs=-1,
            )
            lof.fit(X_scaled)

            # Calibrare LOF
            lof_decisions = lof.decision_function(X_scaled)
            lof_decision_mean = float(lof_decisions.mean())
            lof_decision_std = float(lof_decisions.std()) + 1e-6

            with self._lock:
                self._scaler = scaler
                self._isolation_forest = iso_forest
                self._lof = lof
                self._is_trained = True
                self._training_samples = len(feature_vectors)
                # Calibrare Isolation Forest
                self._if_decision_mean = if_decision_mean
                self._if_decision_std = if_decision_std
                # Calibrare LOF
                self._lof_decision_mean = lof_decision_mean
                self._lof_decision_std = lof_decision_std

            logger.info("[ML] Modele antrenate cu succes pe %d eșantioane.", len(feature_vectors))
            return True

        except Exception as exc:
            logger.error("[ML] Eroare la antrenarea modelelor: %s", exc)
            return False

    def score(self, feature_vector: list) -> dict:
        """Calculează scorurile de anomalie din toate modelele pentru un vector de caracteristici.

        Scorurile sunt calibrate față de distribuția datelor de antrenare:
        - Un scor de 0 → comportament tipic traficului de antrenare
        - Un scor de 1 → outlier extrem față de traficul de antrenare

        Args:
            feature_vector: Vector de caracteristici (listă de float-uri).

        Returns:
            Dicționar cu:
            - isolation_forest_score: float 0-1 (1 = outlier extrem)
            - lof_score: float 0-1 (1 = outlier extrem)
            - available: bool — True dacă modelele sunt disponibile
        """
        if not _SKLEARN_AVAILABLE:
            return {'isolation_forest_score': 0.0, 'lof_score': 0.0, 'available': False}

        with self._lock:
            if not self._is_trained:
                return {'isolation_forest_score': 0.0, 'lof_score': 0.0, 'available': False}

            try:
                import numpy as np

                X = np.array([feature_vector], dtype=float)
                X_scaled = self._scaler.transform(X)

                # Isolation Forest — decision_function returnează valorile
                # relativ la granița de decizie (0 = granița, pozitiv = inlier).
                # Normalizăm folosind statisticile de antrenare:
                # z-score față de medie, inversat (anomaliile au z negativ mare).
                d_if = self._isolation_forest.decision_function(X_scaled)[0]
                z_if = (d_if - self._if_decision_mean) / self._if_decision_std
                # -z_if: anomaliile au z < 0 → -z > 0 → scor mare
                # Mapăm z la [0, 1] cu sigmoid-like: 2 deviatii std = scor 0.9
                if_score = max(0.0, min(1.0, 0.5 - z_if / 4.0))

                # LOF — la fel, calibrat față de distribuția de antrenare
                d_lof = self._lof.decision_function(X_scaled)[0]
                z_lof = (d_lof - self._lof_decision_mean) / self._lof_decision_std
                lof_score = max(0.0, min(1.0, 0.5 - z_lof / 4.0))

                return {
                    'isolation_forest_score': if_score,
                    'lof_score': lof_score,
                    'available': True,
                }

            except Exception as exc:
                logger.debug("[ML] Eroare la scoring: %s", exc)
                return {'isolation_forest_score': 0.0, 'lof_score': 0.0, 'available': False}


# Instanța globală a modelelor (singleton partajat între threads)
anomaly_models = AnomalyModels()
