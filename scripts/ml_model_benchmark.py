#!/usr/bin/env python3
"""
Script de benchmark pentru modelele ML de detectare a anomaliilor.

Generează trafic sintetic (normal + atacuri) și verifică acuratețea modelelor.

Utilizare:
    cd /opt/school-network-security
    python scripts/ml_model_benchmark.py
"""
import sys
import os
import time
import random
import json
from datetime import datetime

# Adăugăm rădăcina proiectului în path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def generate_normal_packet(ip: str) -> dict:
    """Generează un pachet de trafic normal (navigare web, DNS, etc.)."""
    protocols = ['TCP', 'UDP', 'TCP', 'TCP', 'DNS']
    protocol = random.choice(protocols)
    common_ports = [80, 443, 53, 8080, 8443, 22, 25, 587, 993]
    return {
        'src_ip': ip,
        'dst_ip': f'10.0.0.{random.randint(1, 254)}',
        'protocol': protocol,
        'dst_port': random.choice(common_ports),
        'size': random.randint(64, 1500),
        'timestamp': time.time() - random.uniform(0, 60),
        'is_tcp_syn': protocol == 'TCP' and random.random() < 0.1,
        'is_tcp_ack': protocol == 'TCP' and random.random() < 0.7,
        'dns_query': f'site{random.randint(1, 100)}.example.com' if protocol == 'DNS' else None,
        'is_failed': False,
    }


def generate_port_scan_packet(ip: str, port_num: int) -> dict:
    """Generează un pachet de port scan."""
    return {
        'src_ip': ip,
        'dst_ip': f'192.168.1.{random.randint(1, 254)}',
        'protocol': 'TCP',
        'dst_port': port_num,
        'size': 64,
        'timestamp': time.time() - random.uniform(0, 10),
        'is_tcp_syn': True,
        'is_tcp_ack': False,
        'dns_query': None,
        'is_failed': True,
    }


def generate_brute_force_packet(ip: str) -> dict:
    """Generează un pachet de brute force SSH/RDP."""
    return {
        'src_ip': ip,
        'dst_ip': '192.168.1.100',
        'protocol': 'TCP',
        'dst_port': random.choice([22, 3389, 21, 23]),
        'size': random.randint(64, 256),
        'timestamp': time.time() - random.uniform(0, 30),
        'is_tcp_syn': True,
        'is_tcp_ack': False,
        'dns_query': None,
        'is_failed': random.random() < 0.8,
    }


def generate_flood_packet(ip: str) -> dict:
    """Generează un pachet de flooding (DDoS)."""
    return {
        'src_ip': ip,
        'dst_ip': '192.168.1.1',
        'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
        'dst_port': random.choice([80, 443]),
        'size': random.randint(1000, 65535),
        'timestamp': time.time() - random.uniform(0, 5),
        'is_tcp_syn': True,
        'is_tcp_ack': False,
        'dns_query': None,
        'is_failed': False,
    }


def build_ip_buffer(packets: list) -> list:
    """Construiește buffer-ul unui IP din lista de pachete."""
    return packets


def run_benchmark():
    """Rulează benchmark-ul complet."""
    print("=" * 60)
    print("  SchoolSec ML Anomaly Detection Benchmark")
    print("=" * 60)
    print()

    # Verificăm dependențele
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.neighbors import LocalOutlierFactor
        import numpy as np
        print("✅ scikit-learn disponibil")
    except ImportError:
        print("❌ scikit-learn nu este instalat!")
        print("   Instalați cu: pip install scikit-learn")
        sys.exit(1)

    from app.ml.features import extract_features, features_to_vector, FEATURE_KEYS
    from app.ml.models import AnomalyModels

    print(f"✅ Module ML disponibile ({len(FEATURE_KEYS)} caracteristici)")
    print()

    # Generăm trafic sintetic
    normal_ips = [f'192.168.1.{i}' for i in range(1, 51)]      # 50 IP-uri normale
    attack_ips = {
        'port_scan': '10.0.0.100',
        'brute_force': '10.0.0.101',
        'flood': '10.0.0.102',
    }

    print("📊 Generare trafic sintetic...")

    # Trafic normal
    normal_buffers = {}
    for ip in normal_ips:
        packets = [generate_normal_packet(ip) for _ in range(random.randint(50, 200))]
        normal_buffers[ip] = packets

    # Trafic de atac
    attack_buffers = {
        attack_ips['port_scan']:    [generate_port_scan_packet(attack_ips['port_scan'], p)
                                     for p in range(1, 300)],
        attack_ips['brute_force']:  [generate_brute_force_packet(attack_ips['brute_force'])
                                     for _ in range(150)],
        attack_ips['flood']:        [generate_flood_packet(attack_ips['flood'])
                                     for _ in range(400)],
    }

    # Extragem caracteristici
    print("🔧 Extragere caracteristici...")

    normal_features = []
    for ip, buf in normal_buffers.items():
        feat = extract_features(buf, window_seconds=60.0)
        normal_features.append((ip, feat, features_to_vector(feat), False))

    attack_features = []
    for ip, buf in attack_buffers.items():
        feat = extract_features(buf, window_seconds=60.0)
        attack_features.append((ip, feat, features_to_vector(feat), True))

    print(f"   Normal: {len(normal_features)} IP-uri")
    print(f"   Atacuri: {len(attack_features)} IP-uri")
    print()

    # Antrenăm modelele cu trafic normal
    models = AnomalyModels()
    training_vectors = [vec for _, _, vec, _ in normal_features]

    print("🤖 Antrenare modele ML...")
    t0 = time.perf_counter()
    success = models.train(training_vectors)
    t1 = time.perf_counter()

    if not success:
        print("❌ Antrenarea modelelor a eșuat!")
        sys.exit(1)

    print(f"✅ Modele antrenate în {(t1 - t0) * 1000:.1f}ms pe {len(training_vectors)} eșantioane")
    print()

    # Evaluăm performanța
    print("📈 Evaluare performanță...")
    print()

    all_samples = normal_features + attack_features
    results = []

    for ip, feat, vec, is_attack in all_samples:
        t0 = time.perf_counter()
        scores = models.score(vec)
        t1 = time.perf_counter()
        latency_us = (t1 - t0) * 1_000_000

        combined_score = (
            scores['isolation_forest_score'] * 0.5 +
            scores['lof_score'] * 0.5
        ) * 100

        results.append({
            'ip': ip,
            'is_attack': is_attack,
            'if_score': scores['isolation_forest_score'],
            'lof_score': scores['lof_score'],
            'combined': combined_score,
            'latency_us': latency_us,
        })

    # Calculăm metrici (prag: combined >= 60 = anomalie)
    THRESHOLD = 60.0

    tp = sum(1 for r in results if r['is_attack'] and r['combined'] >= THRESHOLD)
    fp = sum(1 for r in results if not r['is_attack'] and r['combined'] >= THRESHOLD)
    tn = sum(1 for r in results if not r['is_attack'] and r['combined'] < THRESHOLD)
    fn = sum(1 for r in results if r['is_attack'] and r['combined'] < THRESHOLD)

    precision  = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall     = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1         = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr        = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    latencies = [r['latency_us'] for r in results]
    avg_latency = sum(latencies) / len(latencies)
    max_latency = max(latencies)

    # Afișăm rezultatele per IP de atac
    print("  Scoruri atac:")
    for r in results:
        if r['is_attack']:
            detected = r['combined'] >= THRESHOLD
            print(f"    {r['ip']:20s}  IF={r['if_score']:.3f}  LOF={r['lof_score']:.3f}  "
                  f"Combinat={r['combined']:.1f}/100  "
                  f"{'✅ DETECTAT' if detected else '❌ RATAT'}")

    print()
    print("  Scoruri normale (câteva exemple):")
    normal_results = [r for r in results if not r['is_attack']][:5]
    for r in normal_results:
        flagged = r['combined'] >= THRESHOLD
        print(f"    {r['ip']:20s}  Combinat={r['combined']:.1f}/100  "
              f"{'⚠️ FP' if flagged else '✅ OK'}")

    print()
    print("=" * 60)
    print("  REZULTATE BENCHMARK")
    print("=" * 60)
    print(f"  Pragul anomalie:    {THRESHOLD}/100")
    print(f"  True Positives:     {tp}/{len(attack_features)}")
    print(f"  True Negatives:     {tn}/{len(normal_features)}")
    print(f"  False Positives:    {fp}/{len(normal_features)}")
    print(f"  False Negatives:    {fn}/{len(attack_features)}")
    print()
    print(f"  Precision:          {precision:.1%}")
    print(f"  Recall (TPR):       {recall:.1%}")
    print(f"  F1 Score:           {f1:.1%}")
    print(f"  False Positive Rate:{fpr:.1%}")
    print()
    print(f"  Latență scoring:    {avg_latency:.1f}µs medie / {max_latency:.1f}µs max")
    print("=" * 60)

    # Caracteristici cu cele mai mari valori pentru IP-urile de atac
    print()
    print("📊 Top caracteristici anomale (atacuri vs normale):")
    from app.ml.features import FEATURE_KEYS
    attack_vecs  = np.array([vec for _, _, vec, is_attack in all_samples if is_attack])
    normal_vecs  = np.array([vec for _, _, vec, is_attack in all_samples if not is_attack])

    if len(attack_vecs) > 0 and len(normal_vecs) > 0:
        attack_means = attack_vecs.mean(axis=0)
        normal_means = normal_vecs.mean(axis=0)
        diffs = abs(attack_means - normal_means)
        top_features = sorted(zip(FEATURE_KEYS, diffs), key=lambda x: x[1], reverse=True)[:5]
        for feat, diff in top_features:
            print(f"   {feat:35s} Δ={diff:.2f}")

    print()
    if f1 >= 0.7:
        print("✅ Performanță acceptabilă (F1 ≥ 0.70)")
    else:
        print("⚠️  Performanță sub așteptări — mai multe date de antrenare pot îmbunătăți rezultatele.")

    return f1


if __name__ == '__main__':
    score = run_benchmark()
    sys.exit(0 if score >= 0.5 else 1)
