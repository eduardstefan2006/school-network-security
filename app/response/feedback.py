"""
Sistem de feedback și îmbunătățire continuă.
Administratorii validează sau resping răspunsurile automate, iar feedback-ul
este utilizat pentru ajustarea modelelor ML.
"""
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class FeedbackProcessor:
    """Procesează feedback-ul adminului și îmbunătățește modelele ML."""

    def record_feedback(self, alert_id: int, feedback_type: str,
                        admin_id: int, admin_comment: str = None) -> object:
        """
        Înregistrează feedback-ul administratorului pentru un răspuns automat.

        :param alert_id: ID-ul alertei evaluate
        :param feedback_type: Tipul feedback-ului: 'confirmed' | 'false_positive' | 'partial'
        :param admin_id: ID-ul utilizatorului admin care trimite feedback-ul
        :param admin_comment: Comentariu opțional
        :returns: Obiectul ResponseFeedback creat
        """
        try:
            from app import db
            from app.models import ResponseFeedback, Alert

            alert = db.session.get(Alert, alert_id)
            if not alert:
                logger.warning('[Feedback] Alertă %d inexistentă', alert_id)
                return None

            # Verificăm dacă există deja feedback pentru această alertă
            existing = ResponseFeedback.query.filter_by(alert_id=alert_id).first()
            if existing:
                # Actualizăm feedback-ul existent
                existing.feedback_type = feedback_type
                existing.comment = admin_comment
                existing.admin_id = admin_id
                existing.created_at = datetime.now(timezone.utc)
                feedback = existing
            else:
                feedback = ResponseFeedback(
                    alert_id=alert_id,
                    feedback_type=feedback_type,
                    comment=admin_comment,
                    admin_id=admin_id,
                )
                db.session.add(feedback)

            # Dacă este fals pozitiv → deblocăm IP-ul și resursele asociate
            if feedback_type == 'false_positive' and alert.source_ip:
                self._unblock_for_false_positive(alert.source_ip)

            db.session.commit()
            logger.info(
                '[Feedback] Feedback %s înregistrat pentru alerta %d',
                feedback_type, alert_id,
            )
            return feedback

        except Exception as exc:
            logger.error('[Feedback] Eroare la înregistrarea feedback-ului: %s', exc)
            try:
                from app import db
                db.session.rollback()
            except Exception:
                pass
            return None

    def _unblock_for_false_positive(self, source_ip: str) -> None:
        """
        Deblochează un IP și resursele asociate identificate ca fals pozitiv.
        """
        try:
            from app.response.blocker import response_blocker
            response_blocker.unblock_ip(source_ip)
            response_blocker.unblock_mac_for_ip(source_ip)
            logger.info('[Feedback] IP %s deblocat (fals pozitiv)', source_ip)
        except Exception as exc:
            logger.error('[Feedback] Eroare la deblocare fals pozitiv %s: %s', source_ip, exc)

    def get_feedback_stats(self, hours: int = 24) -> dict:
        """
        Calculează statisticile feedback-ului din ultimele `hours` ore.

        :param hours: Intervalul de timp pentru calculul statisticilor
        :returns: Dicționar cu statistici de feedback
        """
        try:
            from app.models import ResponseFeedback
            from datetime import timedelta

            since = datetime.now(timezone.utc) - timedelta(hours=hours)
            feedbacks = ResponseFeedback.query.filter(
                ResponseFeedback.created_at >= since
            ).all()

            total = len(feedbacks)
            confirmed = sum(1 for f in feedbacks if f.feedback_type == 'confirmed')
            false_positives = sum(1 for f in feedbacks if f.feedback_type == 'false_positive')
            partial = sum(1 for f in feedbacks if f.feedback_type == 'partial')

            return {
                'total': total,
                'confirmed': confirmed,
                'false_positives': false_positives,
                'partial': partial,
                'confirmed_ratio': round(confirmed / total * 100, 1) if total > 0 else 0.0,
                'false_positive_ratio': round(false_positives / total * 100, 1) if total > 0 else 0.0,
            }
        except Exception as exc:
            logger.error('[Feedback] Eroare la calculul statisticilor: %s', exc)
            return {
                'total': 0, 'confirmed': 0, 'false_positives': 0,
                'partial': 0, 'confirmed_ratio': 0.0, 'false_positive_ratio': 0.0,
            }


# Instanța singleton folosită de orchestrator
feedback_processor = FeedbackProcessor()
