"""
Orchestratorul de răspuns autonom la amenințări.
Coordonează escaladarea, blocarea, notificările și crearea de incidente
pentru fiecare amenințare detectată cu scor de anomalie > 40.
"""
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class ResponseOrchestrator:
    """Coordonează toate componentele de răspuns autonom."""

    def __init__(self):
        from app.response.escalator import threat_escalator
        from app.response.blocker import response_blocker
        from app.response.feedback import feedback_processor

        self.escalator = threat_escalator
        self.blocker = response_blocker
        self.feedback = feedback_processor

    def handle_threat(self, anomaly_score: float, source_ip: str, alert_data: dict) -> dict:
        """
        Fluxul principal de orchestrare a răspunsului la o amenințare.

        Pași:
        1. Escaladare → determină nivelul de severitate
        2. Blocare automată (dacă este configurată)
        3. Trimitere notificări
        4. Creare ticket incident (dacă este critic)
        5. Logare acțiune de răspuns

        :param anomaly_score: Scorul de anomalie ML (0-100)
        :param source_ip: IP-ul sursă al amenințării
        :param alert_data: Datele alertei (alert_id, alert_type, message, timestamp)
        :returns: Configurarea severității utilizată
        """
        try:
            from flask import current_app
            if not current_app.config.get('RESPONSE_ENABLED', True):
                return {}
        except Exception:
            return {}

        # Pas 1: Escaladare
        severity = self.escalator.escalate(source_ip, anomaly_score, alert_data)

        # Pas 2: Blocare automată
        if severity.get('auto_block'):
            try:
                block_result = self.blocker.block_threat(source_ip, alert_data, severity)
                alert_data['block_result'] = block_result
            except Exception as exc:
                logger.error('[Orchestrator] Eroare la blocarea IP %s: %s', source_ip, exc)

        # Pas 3: Notificări
        if severity.get('notification'):
            self._send_notifications(source_ip, severity, anomaly_score, alert_data)

        # Pas 4: Creare incident (pentru amenințări critice)
        if severity.get('create_incident'):
            try:
                incident = self._create_incident(source_ip, severity, anomaly_score, alert_data)
                if incident:
                    alert_data['incident_id'] = incident.id
            except Exception as exc:
                logger.error('[Orchestrator] Eroare la crearea incidentului: %s', exc)

        # Pas 5: Logare acțiune de răspuns globală
        self._log_response_action(source_ip, severity, anomaly_score, alert_data)

        return severity

    def _send_notifications(self, source_ip: str, severity: dict,
                            anomaly_score: float, alert_data: dict) -> None:
        """Trimite notificări prin Telegram (și email dacă este configurat)."""
        try:
            from flask import current_app
            cfg = current_app.config

            label = severity.get('label', severity.get('level', '').upper())
            alert_type = alert_data.get('alert_type', 'unknown')
            message = (
                f'🚨 Răspuns Automat [{label}] - {source_ip}\n'
                f'Tip: {alert_type} | Scor: {anomaly_score:.1f}/100\n'
                f'Acțiune: {severity.get("action", "N/A")}'
            )

            if cfg.get('TELEGRAM_ENABLED'):
                notification_data = {
                    'alert_type': f'response_{alert_type}',
                    'source_ip': source_ip,
                    'severity': severity['level'],
                    'message': message,
                    'timestamp': alert_data.get('timestamp', datetime.now(timezone.utc)),
                    'anomaly_score': anomaly_score,
                }
                from app.notifications.telegram import send_alert_notification
                send_alert_notification(notification_data, cfg)

        except Exception as exc:
            logger.warning('[Orchestrator] Eroare la trimiterea notificărilor: %s', exc)

    def _create_incident(self, source_ip: str, severity: dict,
                         anomaly_score: float, alert_data: dict) -> object:
        """Creează automat un ticket de incident pentru amenințările critice."""
        try:
            from app import db
            from app.models import IncidentTicket

            alert_type = alert_data.get('alert_type', 'unknown')
            description = (
                f'Incident creat automat de sistemul de răspuns Faza 3.\n'
                f'IP: {source_ip} | Scor anomalie: {anomaly_score:.1f}/100\n'
                f'Tip alertă: {alert_type}\n'
                f'Mesaj: {alert_data.get("message", "")}'
            )

            incident = IncidentTicket(
                source_ip=source_ip,
                threat_type=alert_type,
                severity=severity['level'],
                anomaly_score=anomaly_score,
                description=description,
                status='open',
            )
            db.session.add(incident)
            db.session.commit()
            logger.info('[Orchestrator] Incident creat: ID=%d pentru IP %s', incident.id, source_ip)
            return incident

        except Exception as exc:
            logger.error('[Orchestrator] Eroare la crearea incidentului: %s', exc)
            try:
                from app import db
                db.session.rollback()
            except Exception:
                pass
            return None

    @staticmethod
    def _log_response_action(source_ip: str, severity: dict,
                             anomaly_score: float, alert_data: dict) -> None:
        """Logează acțiunea de răspuns global în jurnalul de securitate."""
        try:
            from app import db
            from app.models import SecurityLog

            log = SecurityLog(
                event_type='response_action',
                source_ip=source_ip,
                message=(
                    f'[Faza3] Răspuns autonom: {severity.get("action", "N/A")} '
                    f'pentru {source_ip} (severitate: {severity["level"]}, '
                    f'scor: {anomaly_score:.1f})'
                ),
                severity='info' if not severity.get('auto_block') else 'warning',
            )
            db.session.add(log)
            db.session.commit()
        except Exception as exc:
            logger.warning('[Orchestrator] Eroare la logarea acțiunii de răspuns: %s', exc)

    def get_metrics(self, hours: int = 24) -> dict:
        """
        Calculează metricile de eficiență a sistemului de răspuns.

        :param hours: Intervalul de timp (ore) pentru calculul metricilor
        :returns: Dicționar cu metricile sistemului
        """
        try:
            from app.models import Alert, ResponseAction, IncidentTicket
            from datetime import timedelta

            since = datetime.now(timezone.utc) - timedelta(hours=hours)

            total_threats = Alert.query.filter(Alert.timestamp >= since).count()
            auto_blocked = ResponseAction.query.filter(
                ResponseAction.created_at >= since,
                ResponseAction.action_type == 'block_ip',
            ).count()
            incidents = IncidentTicket.query.filter(
                IncidentTicket.created_at >= since
            ).count()

            feedback_stats = self.feedback.get_feedback_stats(hours=hours)

            return {
                'total_threats': total_threats,
                'auto_blocked': auto_blocked,
                'incidents_created': incidents,
                'confirmed_ratio': feedback_stats['confirmed_ratio'],
                'false_positive_ratio': feedback_stats['false_positive_ratio'],
                'feedback_total': feedback_stats['total'],
            }
        except Exception as exc:
            logger.error('[Orchestrator] Eroare la calculul metricilor: %s', exc)
            return {
                'total_threats': 0, 'auto_blocked': 0, 'incidents_created': 0,
                'confirmed_ratio': 0.0, 'false_positive_ratio': 0.0, 'feedback_total': 0,
            }


# Instanța singleton utilizată în întreaga aplicație
orchestrator = ResponseOrchestrator()
