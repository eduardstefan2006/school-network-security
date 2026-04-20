#!/usr/bin/env python3
"""Teste minime pentru pragurile și fallback-ul de antrenare ML."""
import os
import sys

# Adăugăm rădăcina proiectului în sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_pass_count = 0
_fail_count = 0


def _assert(condition, description):
    global _pass_count, _fail_count
    if condition:
        print(f"  [PASS] {description}")
        _pass_count += 1
    else:
        print(f"  [FAIL] {description}")
        _fail_count += 1


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAINER_PATH = os.path.join(ROOT_DIR, 'app', 'ml', 'trainer.py')
DATA_COLLECTOR_PATH = os.path.join(ROOT_DIR, 'app', 'ml', 'data_collector.py')


def _read(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def test_trainer_default_thresholds_and_logging():
    print("\n--- trainer.py praguri + logging ---")
    source = _read(TRAINER_PATH)

    _assert("_MIN_DB_SAMPLES = int(os.environ.get('ML_MIN_DB_SAMPLES', 20))" in source, "_MIN_DB_SAMPLES implicit este 20 și configurabil prin env")
    _assert("_MIN_BUFFER_SAMPLES = int(os.environ.get('ML_MIN_BUFFER_SAMPLES', 5))" in source, "_MIN_BUFFER_SAMPLES implicit este 5 și configurabil prin env")
    _assert('ML_MIN_DB_SAMPLES' in source, "_trainer_loop folosește pragul configurabil ML_MIN_DB_SAMPLES")
    _assert('ML_MIN_BUFFER_SAMPLES' in source, "_trainer_loop folosește pragul configurabil ML_MIN_BUFFER_SAMPLES")
    _assert('Date insuficiente în BD' in source, "_trainer_loop loghează clar când BD nu are suficiente date")
    _assert('Fallback indisponibil' in source, "_trainer_loop loghează clar când fallback-ul din buffer nu are suficiente date")


def test_config_ml_threshold_defaults():
    print("\n--- config.py praguri ML ---")
    from config import Config

    _assert(Config.ML_MIN_DB_SAMPLES == 20, "Config.ML_MIN_DB_SAMPLES implicit este 20")
    _assert(Config.ML_MIN_BUFFER_SAMPLES == 5, "Config.ML_MIN_BUFFER_SAMPLES implicit este 5")


def test_data_collector_no_zero_ppm_skip():
    print("\n--- data_collector.py filtrare sparse ---")
    source = _read(DATA_COLLECTOR_PATH)
    _assert('packets_per_minute' not in source, "_flush_to_db nu mai sare peste features cu packets_per_minute=0")


if __name__ == '__main__':
    test_trainer_default_thresholds_and_logging()
    test_config_ml_threshold_defaults()
    test_data_collector_no_zero_ppm_skip()

    print(f"\n{'='*40}")
    print(f"Rezultat: {_pass_count} PASS, {_fail_count} FAIL")
    if _fail_count:
        print("EȘEC: unele teste au picat.")
        sys.exit(1)
    print("SUCCES: toate testele au trecut.")
    sys.exit(0)
