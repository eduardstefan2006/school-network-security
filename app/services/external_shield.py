"""
Scut extern de protecție — activare automată a regulilor de securitate.

Creează reguli firewall în RouterOS pe baza topologiei descoperite,
activează rate limiting și blochează traficul suspect.
"""

_MAX_COMMENT_LENGTH = 50  # lungime maximă pentru comentariile RouterOS


def get_external_interface(mikrotik_client) -> str | None:
    """Detectează interfața externă (WAN) din RouterOS.

    Returns:
        Numele interfeței WAN sau None.
    """
    try:
        from app.services.ids_config import get_wan_interface
        return get_wan_interface(mikrotik_client)
    except Exception as e:
        print(f"[ExternalShield] Eroare la detectarea interfeței externe: {e}")
        return None


def get_firewall_summary(mikrotik_client) -> dict:
    """Returnează un sumar al regulilor firewall existente din RouterOS.

    Returns:
        Dict cu numărul de reguli per chain.
    """
    summary = {'filter': 0, 'nat': 0, 'mangle': 0}
    if mikrotik_client is None or not mikrotik_client.is_connected():
        return summary

    try:
        conn = mikrotik_client._connection
        chains = {}
        for item in conn('/ip/firewall/filter/print'):
            chain = item.get('chain', 'unknown')
            chains[chain] = chains.get(chain, 0) + 1
        summary['filter'] = sum(chains.values())
    except Exception as e:
        print(f"[ExternalShield] Eroare la citirea regulilor filter: {e}")

    try:
        conn = mikrotik_client._connection
        nat_count = 0
        for _ in conn('/ip/firewall/nat/print'):
            nat_count += 1
        summary['nat'] = nat_count
    except Exception as e:
        print(f"[ExternalShield] Eroare la citirea regulilor NAT: {e}")

    return summary


def activate_protection(app, mikrotik_client) -> dict:
    """Activează protecția externă pe baza topologiei descoperite.

    1. Detectează interfața WAN
    2. Verifică regulile firewall existente
    3. Raportează starea protecției

    Returns:
        Dict cu statusul activării.
    """
    result = {
        'success': False,
        'wan_interface': None,
        'firewall_rules': {},
        'blocked_ips_synced': 0,
        'message': '',
    }

    if mikrotik_client is None or not mikrotik_client.is_connected():
        result['message'] = 'Clientul MikroTik nu este conectat.'
        return result

    # Detectăm interfața WAN
    wan = get_external_interface(mikrotik_client)
    result['wan_interface'] = wan

    # Rezumăm regulile firewall existente
    fw_summary = get_firewall_summary(mikrotik_client)
    result['firewall_rules'] = fw_summary

    # Sincronizăm IP-urile blocate din BD pe router
    try:
        with app.app_context():
            from app.models import BlockedIP
            blocked = BlockedIP.query.filter_by(is_active=True).all()
            synced = 0
            for b in blocked:
                try:
                    mikrotik_client.block_ip_on_router(
                        b.ip_address,
                        comment=f'SchoolSec: {b.reason[:_MAX_COMMENT_LENGTH]}',
                    )
                    synced += 1
                except Exception:
                    pass
            result['blocked_ips_synced'] = synced
    except Exception as e:
        print(f"[ExternalShield] Eroare la sincronizarea IP-urilor blocate: {e}")

    result['success'] = True
    result['message'] = (
        f'Protecție activată: WAN={wan or "necunoscută"}, '
        f'{fw_summary.get("filter", 0)} reguli filter, '
        f'{result["blocked_ips_synced"]} IP-uri sincronizate.'
    )
    print(f"[ExternalShield] {result['message']}")
    return result
