import pyshark
import os
import json
from datetime import datetime
from dotenv import load_dotenv
from collections import defaultdict
from utils.get_pcap import get_pcap
from utils.MicrosoftFilter import  is_microsoft_ip, MICROSOFT_DOMAINS
from utils.ip_check import check_ip_reputation
from utils.mitre_mapping import map_event
from utils.PortAnalyse import analyse_ports
from utils.mitre_rules import apply_mitre_rules



# Données de géolocalisation d'exemple
GEO_DATA = {
    "23.50.224.8":  {"country": "US", "latitude": "34.05361", "longitude": "-118.24550"},
    "239.255.255.250": {"country": "Inconnu", "latitude": None, "longitude": None},
    "172.17.8.109": {"country": "Inconnu", "latitude": None, "longitude": None},
    "91.121.30.169": {"country": "FR", "latitude": "50.69224", "longitude": "3.20004"},
}

# Chargement des variables d'environnement
load_dotenv()

# Téléchargement du fichier PCAP depuis le serveur distant
# try:
#     get_pcap()
# except Exception as e:
#     print(f"[Erreur] Échec du téléchargement du PCAP : {e}")
#     exit(1)

# Chemin du fichier à analyser
PCAP_FILE = 'logs/capture.pcap'
LOCAL_NETWORK_PREFIX = "172."
VERBOSE = False

# Vérification de l'existence du fichier PCAP
if not os.path.exists(PCAP_FILE):
    print(f"[Erreur] Fichier PCAP introuvable à l'emplacement : {PCAP_FILE}")
    exit(1)


# Statistiques globales
stats = {
    "total_packets": 0,
    "kerberos_failures": 0,
    "binary_downloads": 0,
    "tcp_resets": 0,
    "mitre_events": defaultdict(int),
    "port_counts": defaultdict(int),
    "suspicious_ips": set(),
    "ip_details": defaultdict(lambda: {
        "count": 0,
        "ports": set(),
        "protocols": set(),
        "reasons": [],
        "country": "Inconnu",
        "latitude": None,
        "longitude": None,
        "targeted_machines": set()
    })
}

print("Analyse des paquets réseau en cours...")
capture = pyshark.FileCapture(PCAP_FILE, use_json=True, include_raw=True)

for packet in capture:
    try:
        stats["total_packets"] += 1
        ip_src = packet.ip.src
        ip_dst = packet.ip.dst
        proto = packet.highest_layer

         # Intégration du filtrage Microsoft :
        uri = ""
        if hasattr(packet, 'http') and hasattr(packet.http, 'request_full_uri'):
            uri = packet.http.request_full_uri.lower()
        if is_microsoft_ip(ip_src) or is_microsoft_ip(ip_dst) or any(domain in uri for domain in MICROSOFT_DOMAINS):
            continue


        details = stats["ip_details"][ip_src]
        details["count"] += 1
        details["targeted_machines"].add(ip_dst)
        details["protocols"].add(proto)

        # Ports
        dst_port = None
        if hasattr(packet, 'tcp'):
            src_port = int(packet.tcp.srcport)
            dst_port = int(packet.tcp.dstport)
            stats["port_counts"][src_port] += 1
            stats["port_counts"][dst_port] += 1
            details["ports"].add(src_port)

            if packet.tcp.flags_reset == '1':
                stats["tcp_resets"] += 1
                stats["mitre_events"][map_event("tcp_reset")] += 1

        # Appel des règles MITRE 
        apply_mitre_rules(packet, proto, ip_src, ip_dst, dst_port, stats, details, LOCAL_NETWORK_PREFIX)

    except AttributeError:
        continue

# Traitement par IP
for ip, data in stats["ip_details"].items():
    if data["count"] > 1:
        data["reasons"].append(f"Apparue {data['count']} fois")

    if ip in GEO_DATA:
        data.update(GEO_DATA[ip])

    sensitive_ports = {445, 3389}
    if data["ports"].intersection(sensitive_ports):
        data["reasons"].append(f"Port(s) sensible(s) utilisé(s): {data['ports'].intersection(sensitive_ports)}")

    if not ip.startswith(LOCAL_NETWORK_PREFIX):
        if check_ip_reputation(ip):
            stats["suspicious_ips"].add(ip)
            data["reasons"].append("Réputation négative sur VirusTotal/AbuseIPDB")
        else:
            data["reasons"].append("Adresse IP externe")

# Formatage final des données
for ip, data in stats["ip_details"].items():
    data["ports"] = sorted(list(data["ports"]))
    data["protocols"] = sorted(list(data["protocols"]))
    data["targeted_machines"] = sorted(list(data["targeted_machines"]))

# Top 10 des ports
top_ports = sorted(stats["port_counts"].items(), key=lambda x: x[1], reverse=True)[:10]
analysed_ports = [{"port": port, "count": count} for port, count in top_ports]

# Identifier les machines locales ciblées par des IP suspectes

infected_machines = set()

for ip_suspecte in stats["suspicious_ips"]:
    if ip_suspecte in stats["ip_details"]:
        for target in stats["ip_details"][ip_suspecte]["targeted_machines"]:
            if target.startswith(LOCAL_NETWORK_PREFIX):
                infected_machines.add(target)


# Création du rapport final
rapport = {
    "date_generation": datetime.now().isoformat(),
    "fichier_pcap": PCAP_FILE,
    "statistiques": {
        "total_paquets": stats["total_packets"],
        "ips_analysees": len(stats["ip_details"]),
        "echouements_kerberos": stats["kerberos_failures"],
        "telechargements_binaires_http": stats["binary_downloads"],
        "tcp_resets": stats["tcp_resets"],
"ips_suspectes": list(stats["suspicious_ips"]),
"nombre_ips_suspectes": len(stats["suspicious_ips"]),
"machines_possiblement_infectees": sorted(list(infected_machines))
    },
    "mitre_attacks": dict(stats["mitre_events"]),
    "ports_analyse": analysed_ports,
    "ips": dict(stats["ip_details"]),
    "configuration": {
        "reseau_local": LOCAL_NETWORK_PREFIX,
        "analyse_verbose": VERBOSE
    }
}

# Sauvegarde
os.makedirs("data", exist_ok=True)
rapport_path = os.path.join("data", "rapport_analyse.json")
with open(rapport_path, "w", encoding="utf-8") as f:
    json.dump(rapport, f, indent=4)

print("\n--- Rapport d'analyse ---")
print(f"Total de paquets : {stats['total_packets']}")
print(f"Nombre d'IPs analysées : {len(stats['ip_details'])}")
print(f"Échecs Kerberos : {stats['kerberos_failures']}")
print(f"Téléchargements binaires : {stats['binary_downloads']}")
print(f"TCP Resets : {stats['tcp_resets']}")
print(f"IPs suspectes : {len(stats['suspicious_ips'])}")
print(f"Top ports : {analysed_ports}")
print("\nRépartition MITRE ATT&CK :")
for cat, count in stats["mitre_events"].items():
    print(f"- {cat} : {count} événements")
print(f"\nAnalyse sauvegardée dans '{rapport_path}'")