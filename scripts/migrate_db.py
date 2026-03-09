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


_ALLOWED_TABLES = {'network_devices'}


def column_exists(connection, table_name, column_name):
    """Verifică dacă o coloană există într-o tabelă."""
    if table_name not in _ALLOWED_TABLES:
        raise ValueError(f"Tabelă nepermisă: {table_name}")
    result = connection.execute(text(f"PRAGMA table_info({table_name})"))
    columns = [row[1] for row in result]
    return column_name in columns


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

            print("\nMigrare completă!")
            print("Repornește aplicația cu: python run.py")


if __name__ == '__main__':
    migrate()
