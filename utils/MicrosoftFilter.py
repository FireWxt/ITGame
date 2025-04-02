import json
import ipaddress

# Chargement des données de confiance depuis le JSON
with open('data/ip_domain_trust.json', 'r') as f:
    trust_data = json.load(f)

microsoft_data = trust_data['trusted_services'].get('Microsoft', {})
# Les domaines à filtrer
MICROSOFT_DOMAINS = microsoft_data.get('domains', [])
# Conversion des plages IP en objets ip_network
MICROSOFT_IP_RANGES = [ipaddress.ip_network(cidr) for cidr in microsoft_data.get('ip_ranges', [])]

def is_microsoft_ip(ip):
    """
    Vérifie si l'adresse IP appartient à une plage Microsoft issue du JSON.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in MICROSOFT_IP_RANGES)
    except ValueError:
        return False
