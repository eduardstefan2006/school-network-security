"""
Motor de blocare inteligentă a amenințărilor.
Blochează IP-uri, adrese MAC și hostname-uri în funcție de caracteristicile
dispozitivului detectat (MAC randomizat vs. fizic).
"""
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)


def _is_randomized_mac(mac: str) -> bool:
    """
    Detectează dacă o adresă MAC este randomizată (bit U/L = 1 în primul octet).
    Un MAC randomizat are bitul 1 al primului octet setat la 1.
    """
    try:
        first_octet = int(mac.split(':')[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


class ResponseBlocker:
    """Blochează amenințările inteligent pe baza tipului de dispozitiv și identificatorilor disponibili."""

    def block_threat(self, source_ip: str, alert_data: dict, severity: dict) -> dict:
        """
        Blochează o amenințare la nivel de IP, MAC și/sau hostname, în funcție de
        caracteristicile dispozitivului și nivelul de severitate.

        :param source_ip: IP-ul sursă de blocat
        :param alert_data: Datele alertei (alert_type, alert_id, etc.)
        :param severity: Configurarea severității (din escalator)
        :returns: Dicționar cu rezultatele blocării
        """
        result = {
            'ip_blocked': False,
            'mac_blocked': False,
            'hostname_blocked': False,
            'mikrotik_synced': False,
        }

        try:
            from app import db
            from app.models import (
                BlockedIP, BlockedMAC, BlockedHostname,
                NetworkDevice, SecurityLog, ResponseAction,
            )
            from flask import current_app

            alert_type = alert_data.get('alert_type', 'response_block')
            alert_id = alert_data.get('alert_id')
            anomaly_score = alert_data.get('anomaly_score', 0.0)
            block_duration = severity.get('block_duration', 3600)
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=block_duration)
            reason = f'Auto-blocat Faza3: {alert_type}'

            # 1. Blocăm IP-ul
            existing_ip = BlockedIP.query.filter_by(ip_address=source_ip, is_active=True).first()
            if not existing_ip:
                blocked_ip = BlockedIP(
                    ip_address=source_ip,
                    reason=reason,
                    blocked_by='system-response',
                )
                db.session.add(blocked_ip)
                result['ip_blocked'] = True

                # Înregistrăm acțiunea de răspuns
                self._log_action(
                    db, ResponseAction,
                    alert_id=alert_id,
                    source_ip=source_ip,
                    action_type='block_ip',
                    target=source_ip,
                    severity_level=severity['level'],
                    anomaly_score=anomaly_score,
                    expires_at=expires_at,
                )
            else:
                result['ip_blocked'] = True  # Deja blocat

            # 2. Obținem informații despre dispozitiv
            device = NetworkDevice.query.filter_by(ip_address=source_ip).first()

            # 3. Blocăm MAC sau hostname în funcție de tipul adresei MAC
            if device and device.mac_address:
                mac = device.mac_address.upper()
                if not _is_randomized_mac(mac):
                    # MAC fizic → blocăm MAC-ul
                    existing_mac = BlockedMAC.query.filter_by(mac_address=mac, is_active=True).first()
                    if not existing_mac:
                        blocked_mac = BlockedMAC(
                            mac_address=mac,
                            reason=reason,
                            blocked_by='system-response',
                            associated_ip=source_ip,
                        )
                        db.session.add(blocked_mac)
                        result['mac_blocked'] = True

                        self._log_action(
                            db, ResponseAction,
                            alert_id=alert_id,
                            source_ip=source_ip,
                            action_type='block_mac',
                            target=mac,
                            severity_level=severity['level'],
                            anomaly_score=anomaly_score,
                            expires_at=expires_at,
                        )
                    else:
                        result['mac_blocked'] = True
                else:
                    # MAC randomizat → blocăm hostname-ul
                    if device.hostname:
                        hostname_lower = device.hostname.lower()
                        existing_hn = BlockedHostname.query.filter_by(
                            hostname=hostname_lower, is_active=True
                        ).first()
                        if not existing_hn:
                            blocked_hn = BlockedHostname(
                                hostname=hostname_lower,
                                reason=reason,
                                blocked_by='system-response',
                                associated_ip=source_ip,
                                associated_mac=mac,
                            )
                            db.session.add(blocked_hn)
                            result['hostname_blocked'] = True

                            self._log_action(
                                db, ResponseAction,
                                alert_id=alert_id,
                                source_ip=source_ip,
                                action_type='block_hostname',
                                target=hostname_lower,
                                severity_level=severity['level'],
                                anomaly_score=anomaly_score,
                                expires_at=expires_at,
                            )
                        else:
                            result['hostname_blocked'] = True

            # 4. Log de securitate
            log = SecurityLog(
                event_type='auto_block',
                source_ip=source_ip,
                message=(
                    f'[Faza3] IP {source_ip} blocat automat '
                    f'(severitate: {severity["level"]}, scor: {anomaly_score:.1f})'
                ),
                severity='warning',
            )
            db.session.add(log)
            db.session.commit()

            # 5. Sincronizăm cu MikroTik (dacă este conectat)
            try:
                mikrotik = getattr(current_app, 'mikrotik_client', None)
                if mikrotik and mikrotik.is_connected():
                    comment = f'Auto-blocat SchoolSec Faza3: {alert_type}'
                    if result['mac_blocked'] and device and device.mac_address:
                        mikrotik.block_mac_on_router(device.mac_address, comment=comment)
                    elif result['hostname_blocked'] and device and device.hostname:
                        mikrotik.block_hostname_on_router(device.hostname, comment=comment)
                    else:
                        mikrotik.block_ip_on_router(source_ip, comment=comment)
                    result['mikrotik_synced'] = True
            except Exception as exc:
                logger.warning('[Blocker] Eroare sincronizare MikroTik: %s', exc)

        except Exception as exc:
            logger.error('[Blocker] Eroare la blocarea IP %s: %s', source_ip, exc)
            try:
                from app import db
                db.session.rollback()
            except Exception:
                pass

        return result

    def unblock_target(self, target: str, action_type: str) -> bool:
        """
        Deblochează o țintă (IP, MAC sau hostname) la cererea unui admin.

        :param target: IP, MAC sau hostname de deblocat
        :param action_type: Tipul acțiunii originale ('block_ip', 'block_mac', 'block_hostname')
        :returns: True dacă deblocarea a reușit
        """
        try:
            from app import db
            from app.models import BlockedIP, BlockedMAC, BlockedHostname

            if action_type == 'block_ip':
                record = BlockedIP.query.filter_by(ip_address=target, is_active=True).first()
                if record:
                    record.is_active = False
                    db.session.commit()
                    return True

            elif action_type == 'block_mac':
                record = BlockedMAC.query.filter_by(mac_address=target, is_active=True).first()
                if record:
                    record.is_active = False
                    db.session.commit()
                    return True

            elif action_type == 'block_hostname':
                record = BlockedHostname.query.filter_by(hostname=target, is_active=True).first()
                if record:
                    record.is_active = False
                    db.session.commit()
                    return True

        except Exception as exc:
            logger.error('[Blocker] Eroare la deblocare %s (%s): %s', target, action_type, exc)
            try:
                from app import db
                db.session.rollback()
            except Exception:
                pass

        return False

    def unblock_ip(self, source_ip: str) -> bool:
        """Deblochează IP-ul și resursele asociate (MAC/hostname)."""
        return self.unblock_target(source_ip, 'block_ip')

    def unblock_mac_for_ip(self, source_ip: str) -> bool:
        """Deblochează MAC-ul asociat unui IP."""
        try:
            from app import db
            from app.models import BlockedMAC, BlockedHostname, NetworkDevice

            device = NetworkDevice.query.filter_by(ip_address=source_ip).first()
            if device and device.mac_address:
                mac = device.mac_address.upper()
                if not _is_randomized_mac(mac):
                    return self.unblock_target(mac, 'block_mac')
                elif device.hostname:
                    return self.unblock_target(device.hostname.lower(), 'block_hostname')
        except Exception as exc:
            logger.error('[Blocker] Eroare la deblocarea MAC pentru IP %s: %s', source_ip, exc)
        return False

    @staticmethod
    def _log_action(db, ResponseAction, alert_id, source_ip, action_type,
                    target, severity_level, anomaly_score, expires_at):
        """Creează o înregistrare de audit pentru acțiunea de răspuns."""
        try:
            action = ResponseAction(
                alert_id=alert_id,
                source_ip=source_ip,
                action_type=action_type,
                target=target,
                severity_level=severity_level,
                anomaly_score=anomaly_score,
                expires_at=expires_at,
            )
            db.session.add(action)
        except Exception as exc:
            logger.warning('[Blocker] Eroare la logarea acțiunii %s: %s', action_type, exc)


# Instanța singleton folosită de orchestrator
response_blocker = ResponseBlocker()
