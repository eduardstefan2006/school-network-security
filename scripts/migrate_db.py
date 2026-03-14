#!/usr/bin/env python3
"""
Script de migrare a bazei de date.
Adaugă coloane noi în tabelele existente fără a șterge datele.

Rulare:
    python scripts/migrate_db.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app, db
from sqlalchemy import text


_ALLOWED_TABLES = {'network_devices', 'blocked_hostnames'}


def column_exists(connection, table_name, column_name):
    """Verifică dacă o coloană există într-o tabelă."""
    if table_name not in _ALLOWED_TABLES:
        raise ValueError(f"Tabelă nepermisă: {table_name}")
    result = connection.execute(text(f"PRAGMA table_info({table_name})"))
    columns = [row[1] for row in result]
    return column_name in columns


def table_exists(connection, table_name):
    """Verifică dacă o tabelă există în baza de date."""
    result = connection.execute(text(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=:table"
    ), {'table': table_name})
    return result.fetchone() is not None


def migrate():
    app = create_app('default')
    with app.app_context():
        with db.engine.connect() as conn:
            print("Verificare și migrare baza de date...")

            # Adaugă coloana hostname în network_devices dacă lipsește
            if not column_exists(conn, 'network_devices', 'hostname'):
                print("  Adaug coloana 'hostname' în tabela 'network_devices'...")
                conn.execute(text(
                    "ALTER TABLE network_devices ADD COLUMN hostname VARCHAR(255)"
                ))
                conn.commit()
                print("  ✓ Coloana 'hostname' adăugată cu succes.")
            else:
                print("  ✓ Coloana 'hostname' există deja.")

            # Crează tabela blocked_hostnames dacă nu există
            if not table_exists(conn, 'blocked_hostnames'):
                print("  Creez tabela 'blocked_hostnames'...")
                conn.execute(text("""
                    CREATE TABLE blocked_hostnames (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        hostname VARCHAR(255) UNIQUE NOT NULL,
                        reason TEXT NOT NULL,
                        blocked_by VARCHAR(80) NOT NULL DEFAULT 'system',
                        blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        is_active BOOLEAN NOT NULL DEFAULT 1,
                        associated_ip VARCHAR(45),
                        associated_mac VARCHAR(17),
                        dhcp_server VARCHAR(100)
                    )
                """))
                conn.commit()
                print("  ✓ Tabela 'blocked_hostnames' creată cu succes.")
            else:
                print("  ✓ Tabela 'blocked_hostnames' există deja.")

            print("\nMigrare completă!")
            print("Repornește aplicația cu: python run.py")


if __name__ == '__main__':
    migrate()
