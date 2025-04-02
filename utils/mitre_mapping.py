MITRE_MAPPING = {
    "kerberos_error": "Credential Access",
    "tcp_reset": "Defense Evasion",
    "http_bin_download": "Execution",
    "suspicious_port": "Initial Access",
    "port_scan_detected": "Discovery"
}

def map_event(event_type):
    """Retourne la tactique MITRE ATT&CK 
    """
    return MITRE_MAPPING.get(event_type, "Unknown")

def count_events(mapped_events):
    """
    Compte le nombre d’événements par catégorie MITRE ATT&CK.
    """
    counts = {}
    for tactic in mapped_events:
        if tactic not in counts:
            counts[tactic] = 0
        counts[tactic] += 1
    return counts
