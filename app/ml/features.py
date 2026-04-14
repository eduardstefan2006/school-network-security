"""
Inginerie caracteristici (Feature Engineering) pentru detectarea ML a anomaliilor.

Extrage 20+ caracteristici per IP pe minut din bufferul de pachete.
"""
import math
import time
from collections import defaultdict

# Valoarea maximă pentru varianța porturilor (cap pentru normalizare)
_PORT_VARIANCE_CAP = 1_000_000_000  # 1e9 — porturile maxime sunt 65535, varianța nu poate depăși ~10^9
# Valoarea maximă pentru raportul SYN/ACK (protecție împotriva valorilor infinite)
_SYN_ACK_RATIO_CAP = 100.0  # Un IP legitim nu trimite mai mult de 100 SYN per ACK


def compute_protocol_entropy(protocol_counts: dict) -> float:
    """Calculează entropia Shannon a distribuției protocoalelor.

    O valoare ridicată indică trafic variat (normal); o valoare scăzută
    indică trafic concentrat pe un singur protocol (posibil suspect).
    """
    total = sum(protocol_counts.values())
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in protocol_counts.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def compute_port_variance(ports: list) -> float:
    """Calculează varianța distribuției porturilor destinație.

    Varianță mare → porturile sunt răspândite (posibil port scan).
    Varianță mică → trafic concentrat pe câteva porturi (normal).
    """
    if not ports:
        return 0.0
    n = len(ports)
    mean = sum(ports) / n
    variance = sum((p - mean) ** 2 for p in ports) / n
    return variance


def extract_features(ip_buffer: list, window_seconds: float = 60.0) -> dict:
    """Extrage vectorul de caracteristici (20+) pentru un IP din bufferul de pachete.

    Args:
        ip_buffer: Listă de dicționare {timestamp, protocol, dst_port, dst_ip,
                   size, is_tcp_syn, is_tcp_ack, dns_query, is_failed}
                   Fiecare element reprezintă un pachet.
        window_seconds: Fereastra de timp pentru calculul caracteristicilor.

    Returns:
        Dicționar cu caracteristicile extrase.
    """
    if not ip_buffer:
        return _empty_features()

    now = time.time()
    cutoff = now - window_seconds

    # Filtrăm pachetele din fereastra de timp
    packets = [p for p in ip_buffer if p.get('timestamp', 0) >= cutoff]
    if not packets:
        return _empty_features()

    n = len(packets)
    total_bytes = sum(p.get('size', 0) for p in packets)

    # Protocoale
    protocol_counts = defaultdict(int)
    for p in packets:
        proto = (p.get('protocol') or 'UNKNOWN').upper()
        protocol_counts[proto] += 1

    tcp_count = protocol_counts.get('TCP', 0)
    udp_count = protocol_counts.get('UDP', 0)
    icmp_count = protocol_counts.get('ICMP', 0)
    dns_count = sum(1 for p in packets if p.get('dns_query'))

    tcp_ratio = tcp_count / n if n > 0 else 0.0
    udp_ratio = udp_count / n if n > 0 else 0.0
    icmp_ratio = icmp_count / n if n > 0 else 0.0
    dns_ratio = dns_count / n if n > 0 else 0.0

    # Porturi destinație
    dst_ports = [p['dst_port'] for p in packets if p.get('dst_port') is not None]
    unique_dst_ports = len(set(dst_ports))

    # IP-uri destinație
    dst_ips = [p['dst_ip'] for p in packets if p.get('dst_ip')]
    unique_dst_ips = len(set(dst_ips))

    # Conexiuni noi vs eșuate
    new_conns = sum(1 for p in packets if p.get('is_tcp_syn') and not p.get('is_tcp_ack'))
    failed_conns = sum(1 for p in packets if p.get('is_failed', False))
    failed_ratio = failed_conns / n if n > 0 else 0.0

    # SYN/ACK ratio
    syn_count = sum(1 for p in packets if p.get('is_tcp_syn'))
    ack_count = sum(1 for p in packets if p.get('is_tcp_ack'))
    syn_ack_ratio = syn_count / ack_count if ack_count > 0 else 0.0

    # Data packets (non-SYN, non-DNS, cu bytes)
    data_packets = sum(1 for p in packets if p.get('size', 0) > 64 and not p.get('is_tcp_syn'))
    data_packet_ratio = data_packets / n if n > 0 else 0.0

    # Bytes per packet
    bytes_per_packet = total_bytes / n if n > 0 else 0.0

    # Varianța porturilor
    port_var = compute_port_variance(dst_ports)

    # Entropia protocoalelor
    proto_entropy = compute_protocol_entropy(dict(protocol_counts))

    # Timestamp-ul primului și ultimului pachet
    timestamps = sorted(p.get('timestamp', now) for p in packets)
    time_since_last = now - timestamps[-1] if timestamps else window_seconds
    time_span = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 1.0

    # Rate-uri per minut
    packets_per_minute = n / (window_seconds / 60.0)
    bytes_per_minute = total_bytes / (window_seconds / 60.0)

    # Ora din zi normalizată (0-1)
    from datetime import datetime, timezone
    hour_of_day = datetime.now(timezone.utc).hour / 23.0

    return {
        'packets_per_minute': packets_per_minute,
        'bytes_per_minute': bytes_per_minute,
        'unique_dst_ports': unique_dst_ports,
        'unique_dst_ips': unique_dst_ips,
        'tcp_ratio': tcp_ratio,
        'udp_ratio': udp_ratio,
        'dns_ratio': dns_ratio,
        'icmp_ratio': icmp_ratio,
        'new_connections_per_minute': new_conns / (window_seconds / 60.0),
        'failed_connections_ratio': failed_ratio,
        'port_variance': min(port_var, _PORT_VARIANCE_CAP),  # limităm pentru normalizare
        'protocol_entropy': proto_entropy,
        'hour_of_day': hour_of_day,
        'bytes_per_packet_avg': bytes_per_packet,
        'packets_per_connection_avg': n / (unique_dst_ips + 1),
        'time_since_last_packet': min(time_since_last, window_seconds),
        'connection_diversity': unique_dst_ips,
        'dns_query_rate': dns_count / (window_seconds / 60.0),
        'syn_ack_ratio': min(syn_ack_ratio, _SYN_ACK_RATIO_CAP),  # limităm
        'data_packet_ratio': data_packet_ratio,
    }


def _empty_features() -> dict:
    """Returnează un vector de caracteristici cu toate valorile zero."""
    return {
        'packets_per_minute': 0.0,
        'bytes_per_minute': 0.0,
        'unique_dst_ports': 0,
        'unique_dst_ips': 0,
        'tcp_ratio': 0.0,
        'udp_ratio': 0.0,
        'dns_ratio': 0.0,
        'icmp_ratio': 0.0,
        'new_connections_per_minute': 0.0,
        'failed_connections_ratio': 0.0,
        'port_variance': 0.0,
        'protocol_entropy': 0.0,
        'hour_of_day': 0.0,
        'bytes_per_packet_avg': 0.0,
        'packets_per_connection_avg': 0.0,
        'time_since_last_packet': 60.0,
        'connection_diversity': 0,
        'dns_query_rate': 0.0,
        'syn_ack_ratio': 0.0,
        'data_packet_ratio': 0.0,
    }


# Cheia ordonată a caracteristicilor — menținută constant pentru vectorii numpy
FEATURE_KEYS = [
    'packets_per_minute',
    'bytes_per_minute',
    'unique_dst_ports',
    'unique_dst_ips',
    'tcp_ratio',
    'udp_ratio',
    'dns_ratio',
    'icmp_ratio',
    'new_connections_per_minute',
    'failed_connections_ratio',
    'port_variance',
    'protocol_entropy',
    'hour_of_day',
    'bytes_per_packet_avg',
    'packets_per_connection_avg',
    'time_since_last_packet',
    'connection_diversity',
    'dns_query_rate',
    'syn_ack_ratio',
    'data_packet_ratio',
]


def features_to_vector(features: dict) -> list:
    """Convertește dicționarul de caracteristici într-un vector ordonat (pentru modele ML)."""
    return [features.get(k, 0.0) for k in FEATURE_KEYS]
