"""
Thread de antrenare și reantrenare periodică a modelelor ML.

Funcționalități:
- Antrenare inițială când sunt disponibile suficiente date
- Reantrenare periodică (implicit la fiecare 24h) cu date din BD
- Fallback: antrenare cu date din buffer-ul curent dacă BD-ul are puține date
"""
import logging
import threading
import time

logger = logging.getLogger(__name__)

# Intervalul de reantrenare (secunde) — implicit 24 ore
_RETRAIN_INTERVAL = 24 * 3600

# Numărul minim de eșantioane în BD pentru reantrenare
_MIN_DB_SAMPLES = 50

# Intervalul de verificare dacă se poate antrena (secunde)
_CHECK_INTERVAL = 60


def _load_training_data_from_db(app, limit: int = 5000) -> list:
    """Încarcă vectorii de caracteristici din baza de date.

    Args:
        app: Instanța Flask.
        limit: Numărul maxim de eșantioane de încărcat.

    Returns:
        Listă de vectori de caracteristici (liste de float-uri).
    """
    import json

    try:
        with app.app_context():
            from app.models import MLTrainingData
            from app.ml.features import features_to_vector

            rows = (
                MLTrainingData.query
                .order_by(MLTrainingData.timestamp.desc())
                .limit(limit)
                .all()
            )

            vectors = []
            for row in rows:
                try:
                    features = json.loads(row.feature_vector)
                    vec = features_to_vector(features)
                    vectors.append(vec)
                except Exception:
                    pass

            return vectors
    except Exception as exc:
        logger.error("[ML Trainer] Eroare la încărcarea datelor din BD: %s", exc)
        return []


def _trainer_loop(app, retrain_interval: int = _RETRAIN_INTERVAL) -> None:
    """Bucla principală a thread-ului de antrenare."""
    from app.ml.models import anomaly_models
    from app.ml.data_collector import data_collector

    logger.info("[ML Trainer] Thread de antrenare pornit.")
    last_retrain = 0.0
    initial_trained = False

    while True:
        try:
            now = time.time()

            # Antrenare inițială sau reantrenare periodică
            should_train = (not initial_trained) or (now - last_retrain >= retrain_interval)

            if should_train:
                # Încearcă să încarce date din BD
                vectors = _load_training_data_from_db(app)

                if len(vectors) < _MIN_DB_SAMPLES:
                    # Fallback la datele din buffer-ul curent
                    buffer_vectors = data_collector.get_feature_vectors_for_training()
                    if len(buffer_vectors) >= 10:
                        vectors = buffer_vectors
                        logger.info(
                            "[ML Trainer] Antrenare cu date din buffer: %d eșantioane.",
                            len(vectors),
                        )

                if vectors:
                    success = anomaly_models.train(vectors)
                    if success:
                        last_retrain = now
                        initial_trained = True
                        logger.info(
                            "[ML Trainer] Modele antrenate cu succes (%d eșantioane).",
                            len(vectors),
                        )
                    else:
                        logger.warning("[ML Trainer] Antrenarea modelelor a eșuat.")
                else:
                    logger.debug(
                        "[ML Trainer] Date insuficiente pentru antrenare "
                        "(min %d eșantioane necesare).", _MIN_DB_SAMPLES
                    )

            # Salvare periodică a caracteristicilor în BD
            data_collector.maybe_save_to_db(app)

            # Curățare buffer-e inactive
            data_collector.cleanup_old_buffers()

        except Exception as exc:
            logger.error("[ML Trainer] Eroare în bucla principală: %s", exc)

        time.sleep(_CHECK_INTERVAL)


def start_ml_trainer(app, retrain_interval: int = _RETRAIN_INTERVAL) -> threading.Thread:
    """Pornește thread-ul daemon de antrenare ML.

    Args:
        app: Instanța Flask.
        retrain_interval: Intervalul de reantrenare în secunde.

    Returns:
        Thread-ul pornit.
    """
    from app.ml.models import anomaly_models

    if not anomaly_models.sklearn_available:
        logger.warning(
            "[ML Trainer] scikit-learn nu este disponibil. "
            "Thread-ul de antrenare nu va fi pornit."
        )
        return None

    thread = threading.Thread(
        target=_trainer_loop,
        args=(app, retrain_interval),
        name='ml-trainer',
        daemon=True,
    )
    thread.start()
    logger.info("[ML Trainer] Thread de antrenare ML pornit (ID: %s).", thread.ident)
    return thread
