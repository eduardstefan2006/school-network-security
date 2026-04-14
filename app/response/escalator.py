"""
Motor de escaladare a amenințărilor.
Mapează scorurile de anomalie la niveluri de severitate și determină
acțiunile automate corespunzătoare.
"""
import logging

logger = logging.getLogger(__name__)

# Regulile de escaladare: severitate → configurare răspuns
ESCALATION_RULES = {
    'low': {
        'score_range': (0, 40),
        'label': 'LOW',
        'action': 'log_only',
        'notification': False,
        'auto_block': False,
    },
    'medium': {
        'score_range': (40, 60),
        'label': 'MEDIUM',
        'action': 'alert_admin',
        'notification': True,
        'auto_block': False,
    },
    'high': {
        'score_range': (60, 80),
        'label': 'HIGH',
        'action': 'auto_block_ip',
        'notification': True,
        'auto_block': True,
        'block_duration': 3600,  # 1 oră
    },
    'critical': {
        'score_range': (80, 101),
        'label': 'CRITICAL',
        'action': 'block_all_identifiers',
        'notification': True,
        'auto_block': True,
        'block_duration': 86400,  # 24 ore
        'create_incident': True,
    },
}


class ThreatEscalator:
    """Determină nivelul de severitate al unei amenințări și declanșează răspunsurile corespunzătoare."""

    def _get_severity(self, anomaly_score: float) -> dict:
        """Returnează configurarea severității corespunzătoare scorului de anomalie."""
        for level, config in ESCALATION_RULES.items():
            low, high = config['score_range']
            if low <= anomaly_score < high:
                return {'level': level, **config}
        # Scor în afara intervalelor cunoscute → tratăm ca critic
        return {'level': 'critical', **ESCALATION_RULES['critical']}

    def escalate(self, source_ip: str, anomaly_score: float, alert_data: dict) -> dict:
        """
        Determină nivelul de severitate și returnează configurarea răspunsului.

        :param source_ip: IP-ul sursă al amenințării
        :param anomaly_score: Scorul de anomalie ML (0-100)
        :param alert_data: Datele alertei (alert_type, message, etc.)
        :returns: Dicționar cu configurarea severității
        """
        severity = self._get_severity(anomaly_score)
        logger.info(
            '[Escalator] IP %s, scor %.1f → severitate %s (acțiune: %s)',
            source_ip, anomaly_score, severity['level'], severity['action'],
        )
        return severity


# Instanța singleton folosită de orchestrator
threat_escalator = ThreatEscalator()
