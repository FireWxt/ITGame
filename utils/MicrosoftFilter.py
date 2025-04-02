import json

# Liste des domaines Microsoft à filtrer 
MICROSOFT_DOMAINS = [
    "microsoft.com", "msedge.net", "live.com", "windows.com",
    "office365.com", "msn.com", "skype.com", "azure.com",
    "bing.com", "msecnd.net", "outlook.com", "onenote.com"
]

MICROSOFT_IP_PREFIXES = [
    "13.", "20.", "40.", "52.", "104.", "134.", "137.", "157.", "168.", "191.", "204."
]

def is_microsoft_ip(ip):
    """
    Vérifie si une adresse IP appartient à un bloc d’adresses Microsoft connu.
    """
    return any(ip.startswith(prefix) for prefix in MICROSOFT_IP_PREFIXES)

def filtrer_microsoft(json_path, output_path):
    """
    Filtre les paquets du fichier JSON en excluant ceux liés à des adresses IP ou domaines Microsoft.
    Enregistre le résultat dans un nouveau fichier JSON.
    """
    with open(json_path, 'r') as f:
        packets = json.load(f)

    filtered_packets = []

    for packet in packets:
        src = packet.get('ip_src', '')
        dst = packet.get('ip_dst', '')
        uri = packet.get('uri', '').lower()

        if is_microsoft_ip(src) or is_microsoft_ip(dst):
            continue

        if any(domain in uri for domain in MICROSOFT_DOMAINS):
            continue

        filtered_packets.append(packet)

    with open(output_path, 'w') as f_out:
        json.dump(filtered_packets, f_out, indent=4)

    return filtered_packets
