from utils.mitre_mapping import map_event

def apply_mitre_rules(packet, proto, ip_src, ip_dst, dst_port, stats, details, LOCAL_NETWORK_PREFIX):
    try:
        # Initial Access
        if not ip_src.startswith(LOCAL_NETWORK_PREFIX) and ip_dst.startswith(LOCAL_NETWORK_PREFIX):
            details["reasons"].append("Connexion externe suspecte (Initial Access)")
            stats["mitre_events"][map_event("initial_access")] += 1

        # Téléchargement de fichier exécutable
        if proto == "HTTP" and hasattr(packet, 'http') and hasattr(packet.http, 'request_full_uri'):
            uri = packet.http.request_full_uri.lower()
            if any(ext in uri for ext in [".bin", ".exe", ".sh", ".bat", ".ps1", ".vbs"]):
                details["reasons"].append(f"Téléchargement de fichier potentiellement malveillant : {uri}")
                stats["mitre_events"][map_event("execution_download")] += 1

        # DNS suspects
        if proto == "DNS" and hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
            domain = packet.dns.qry_name.lower()
            if len(domain) > 30 or any(ext in domain for ext in ['.xyz', '.top', '.tk']):
                stats["mitre_events"][map_event("dns_suspicious")] += 1
                details["reasons"].append(f"Requête DNS suspecte vers {domain}")

        # Persistence
        if details["count"] >= 100:
            details["reasons"].append("Activité régulière suspecte (Persistence)")
            stats["mitre_events"][map_event("persistence_pattern")] += 1

        # Privilege Escalation
        if proto == "KERBEROS":
            details["reasons"].append("Activité Kerberos suspecte (Privilège)")
            stats["mitre_events"][map_event("privilege_escalation")] += 1

        # Exfiltration
        if proto in {"FTP", "SSH", "TLS"} and not ip_dst.startswith(LOCAL_NETWORK_PREFIX) and dst_port in {21, 22, 443}:
            details["reasons"].append("Possible exfiltration de données")
            stats["mitre_events"][map_event("data_exfiltration")] += 1

    except Exception as e:
        print(f"[MITRE RULE ERROR] {e}")
