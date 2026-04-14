"""
Modul de monitorizare a spațiului pe disc cu alerte și curățare automată.
"""
import os
import shutil
from datetime import datetime, timezone
import logging
import gzip

logger = logging.getLogger(__name__)


class DiskMonitor:
    """Monitorizează spațiul pe disc și declanșează alerte/curățări automate."""

    def __init__(self):
        self.app_dir = '/opt/school-network-security'
        self.log_dir = '/opt/school-network-security/logs'
        self.backup_dir = '/home/data'
        self.app = None

        self.thresholds = {
            'yellow': 70,   # Avertisment: începe curățarea
            'red': 85,      # Critic: curățare agresivă
            'black': 95     # Urgență: proceduri de urgență
        }

    def init_app(self, app):
        """Inițializează cu instanța Flask."""
        self.app = app

    def get_disk_status(self):
        """Returnează utilizarea discului pentru directoarele monitorizate."""
        status = {
            'app': self._check_directory(self.app_dir),
            'logs': self._check_directory(self.log_dir),
            'backups': self._check_directory(self.backup_dir),
            'overall': self._check_disk('/')
        }
        return status

    def _check_directory(self, path):
        """Calculează dimensiunea unui director."""
        try:
            total_size = 0
            if os.path.exists(path):
                for dirpath, dirnames, filenames in os.walk(path):
                    for filename in filenames:
                        try:
                            total_size += os.path.getsize(os.path.join(dirpath, filename))
                        except OSError:
                            pass
            return {
                'path': path,
                'size_mb': total_size / (1024 * 1024),
                'size_gb': total_size / (1024 * 1024 * 1024),
                'exists': os.path.exists(path)
            }
        except Exception as e:
            logger.error(f"Error checking directory {path}: {e}")
            return {'path': path, 'size_mb': 0, 'size_gb': 0, 'exists': False}

    def _check_disk(self, path):
        """Verifică procentul de utilizare al discului."""
        try:
            import psutil
            disk = psutil.disk_usage(path)
            return {
                'total_gb': disk.total / (1024 ** 3),
                'used_gb': disk.used / (1024 ** 3),
                'free_gb': disk.free / (1024 ** 3),
                'percent_used': disk.percent
            }
        except ImportError:
            # Fallback dacă psutil nu e instalat: folosim shutil
            try:
                total, used, free = shutil.disk_usage(path)
                percent = (used / total * 100) if total else 0
                return {
                    'total_gb': total / (1024 ** 3),
                    'used_gb': used / (1024 ** 3),
                    'free_gb': free / (1024 ** 3),
                    'percent_used': round(percent, 1)
                }
            except Exception as e:
                logger.error(f"Error checking disk {path}: {e}")
                return {}
        except Exception as e:
            logger.error(f"Error checking disk {path}: {e}")
            return {}

    def check_and_alert(self):
        """Verifică utilizarea discului și declanșează alerte dacă e necesar."""
        status = self.get_disk_status()

        if 'overall' not in status or not status['overall']:
            return {'alert_level': 'ERROR', 'status': status}

        overall = status['overall']
        percent = overall['percent_used']

        alert_level = None
        action_taken = []

        if percent > self.thresholds['black']:
            alert_level = 'BLACK'
            action_taken = self._handle_emergency(status)
        elif percent > self.thresholds['red']:
            alert_level = 'RED'
            action_taken = self._handle_critical(status)
        elif percent > self.thresholds['yellow']:
            alert_level = 'YELLOW'
            action_taken = self._handle_warning(status)

        result = {
            'alert_level': alert_level,
            'status': status,
            'actions_taken': action_taken,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        if alert_level:
            self._send_alert(alert_level, status, action_taken)

        return result

    def _handle_warning(self, status):
        """YELLOW: 70-85% – Începe curățarea."""
        actions = []
        logger.warning(f"Disk usage WARNING: {status['overall']['percent_used']:.1f}%")

        try:
            compressed = self._compress_old_logs(days=7)
            if compressed > 0:
                actions.append(f"Compressed {compressed} log files")
        except Exception as e:
            logger.error(f"Error compressing logs: {e}")

        try:
            archived = self._archive_old_backups(days=30)
            if archived > 0:
                actions.append(f"Archived {archived} backup files")
        except Exception as e:
            logger.error(f"Error archiving backups: {e}")

        return actions

    def _handle_critical(self, status):
        """RED: 85-95% – Curățare agresivă."""
        actions = []
        logger.error(f"Disk usage CRITICAL: {status['overall']['percent_used']:.1f}%")

        try:
            deleted = self._delete_old_logs(days=30)
            if deleted > 0:
                actions.append(f"Deleted {deleted} old log files")
        except Exception as e:
            logger.error(f"Error deleting logs: {e}")

        try:
            archived = self._archive_all_backups()
            if archived > 0:
                actions.append(f"Archived {archived} backup files (CRITICAL)")
        except Exception as e:
            logger.error(f"Error archiving backups: {e}")

        return actions

    def _handle_emergency(self, status):
        """BLACK: >95% – URGENȚĂ."""
        actions = []
        logger.critical(f"Disk usage EMERGENCY: {status['overall']['percent_used']:.1f}%")

        try:
            self._disable_non_critical_logging()
            actions.append("Non-critical logging disabled")
        except Exception as e:
            logger.error(f"Error disabling logging: {e}")

        try:
            deleted = self._delete_old_logs(days=7)
            if deleted > 0:
                actions.append(f"EMERGENCY: Deleted {deleted} recent log files")
        except Exception as e:
            logger.error(f"Error emergency deletion: {e}")

        return actions

    def _compress_old_logs(self, days=7):
        """Comprimă log-urile mai vechi de X zile."""
        if not os.path.exists(self.log_dir):
            return 0

        compressed_count = 0
        now = datetime.now()

        try:
            for filename in os.listdir(self.log_dir):
                if filename.endswith('.log') and not filename.endswith('.gz'):
                    file_path = os.path.join(self.log_dir, filename)
                    file_time = datetime.fromtimestamp(os.path.getmtime(file_path))

                    if (now - file_time).days > days:
                        try:
                            gz_path = f'{file_path}.gz'
                            with open(file_path, 'rb') as f_in:
                                with gzip.open(gz_path, 'wb') as f_out:
                                    f_out.write(f_in.read())
                            os.remove(file_path)
                            compressed_count += 1
                            logger.info(f"Compressed: {filename}")
                        except Exception as e:
                            logger.error(f"Error compressing {filename}: {e}")
        except Exception as e:
            logger.error(f"Error in compress_old_logs: {e}")

        return compressed_count

    def _archive_old_backups(self, days=30):
        """Mută backup-urile mai vechi de X zile în arhivă."""
        if not os.path.exists(self.backup_dir):
            return 0

        archived_count = 0
        archive_dir = os.path.join(self.backup_dir, 'archive')

        try:
            os.makedirs(archive_dir, exist_ok=True)
            now = datetime.now()

            for backup in os.listdir(self.backup_dir):
                if backup == 'archive':
                    continue

                backup_path = os.path.join(self.backup_dir, backup)
                file_time = datetime.fromtimestamp(os.path.getmtime(backup_path))

                if (now - file_time).days > days:
                    try:
                        shutil.move(backup_path, os.path.join(archive_dir, backup))
                        archived_count += 1
                        logger.info(f"Archived: {backup}")
                    except Exception as e:
                        logger.error(f"Error archiving {backup}: {e}")
        except Exception as e:
            logger.error(f"Error in archive_old_backups: {e}")

        return archived_count

    def _archive_all_backups(self):
        """Arhivează TOATE backup-urile (urgență)."""
        if not os.path.exists(self.backup_dir):
            return 0

        archived_count = 0
        archive_dir = os.path.join(self.backup_dir, 'archive')

        try:
            os.makedirs(archive_dir, exist_ok=True)

            for backup in os.listdir(self.backup_dir):
                if backup == 'archive':
                    continue

                backup_path = os.path.join(self.backup_dir, backup)
                try:
                    shutil.move(backup_path, os.path.join(archive_dir, backup))
                    archived_count += 1
                    logger.warning(f"EMERGENCY archived: {backup}")
                except Exception as e:
                    logger.error(f"Error emergency archiving {backup}: {e}")
        except Exception as e:
            logger.error(f"Error in archive_all_backups: {e}")

        return archived_count

    def _delete_old_logs(self, days=30):
        """Șterge log-urile mai vechi de X zile."""
        if not os.path.exists(self.log_dir):
            return 0

        deleted_count = 0
        now = datetime.now()

        try:
            for filename in os.listdir(self.log_dir):
                file_path = os.path.join(self.log_dir, filename)
                file_time = datetime.fromtimestamp(os.path.getmtime(file_path))

                if (now - file_time).days > days:
                    try:
                        if os.path.isfile(file_path):
                            os.remove(file_path)
                            deleted_count += 1
                            logger.warning(f"Deleted old log: {filename}")
                    except Exception as e:
                        logger.error(f"Error deleting {filename}: {e}")
        except Exception as e:
            logger.error(f"Error in delete_old_logs: {e}")

        return deleted_count

    def _disable_non_critical_logging(self):
        """URGENȚĂ: Păstrează doar logurile critice."""
        try:
            import logging as _logging
            for handler in _logging.root.handlers:
                handler.setLevel(_logging.CRITICAL)
            _logging.root.setLevel(_logging.CRITICAL)
            logger.critical("Non-critical logging DISABLED - Emergency mode active")
        except Exception as e:
            logger.error(f"Error disabling logging: {e}")

    def _send_alert(self, level, status, actions):
        """Trimite alertă prin Telegram/notificare dashboard."""
        try:
            from app.services.notifications import notify_admins

            percent = status['overall']['percent_used']

            if level == 'YELLOW':
                emoji = '🟡'
                title = 'DISK SPACE WARNING'
            elif level == 'RED':
                emoji = '🔴'
                title = 'DISK SPACE CRITICAL'
            else:  # BLACK
                emoji = '⚫'
                title = 'DISK SPACE EMERGENCY'

            app_size_gb = status.get('app', {}).get('size_gb', 0)
            logs_size_gb = status.get('logs', {}).get('size_gb', 0)
            backups_size_gb = status.get('backups', {}).get('size_gb', 0)

            message = (
                f"{emoji} {title} {emoji}\n\n"
                f"Disk Usage: {percent:.1f}%\n"
                f"Total: {status['overall']['total_gb']:.1f} GB\n"
                f"Used: {status['overall']['used_gb']:.1f} GB\n"
                f"Free: {status['overall']['free_gb']:.1f} GB\n\n"
                f"📊 Directory Breakdown:\n"
                f"├─ App: {app_size_gb:.1f} GB\n"
                f"├─ Logs: {logs_size_gb:.1f} GB\n"
                f"└─ Backups: {backups_size_gb:.1f} GB\n\n"
                f"✅ Actions Taken:\n"
            )

            if actions:
                for action in actions:
                    message += f"   • {action}\n"
            else:
                message += "   • None (monitoring)\n"

            message += f"\n⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"

            notify_admins(message, alert_level=level)
        except Exception as e:
            logger.error(f"Error sending alert: {e}")


# Instanță globală
disk_monitor = DiskMonitor()
