import pyshark
import os
import json
from datetime import datetime
from dotenv import load_dotenv
from collections import defaultdict
from utils.MicrosoftFilter import is_microsoft_ip
from utils.ip_check import check_ip_reputation
from utils.mitre_mapping import map_event
from utils.PortAnalyse import analyse_ports

# Dictionnaire interne d'exemples pour la géolocalisation
GEO_DATA = {
    "23.50.224.8":  {"country": "US", "latitude": "34.05361", "longitude": "-118.24550"},
    "239.255.255.250": {"country": "Inconnu", "latitude": None, "longitude": None},
    "172.17.8.109": {"country": "Inconnu", "latitude": None, "longitude": None},
    "91.121.30.169": {"country": "FR", "latitude": "50.69224", "longitude": "3.20004"},
}

# Chargement des variables d'environnement (clés API, etc.)
load_dotenv()
PCAP_FILE = 'logs/capture.pcap'
LOCAL_NETWORK_PREFIX = "172."
VERBOSE = False  # Pour affichage détaillé si besoin

# STATISTIQUES GLOBALES
total_packets = 0
kerberos_failures = 0
binary_downloads = 0
tcp_resets = 0
mitre_events = defaultdict(int)
port_counts = defaultdict(int)
suspicious_ips = set()

# Dictionnaire détaillé par IP
ip_details = defaultdict(lambda: {
    "count": 0,
    "ports": set(),
    "protocols": set(),
    "reasons": [],
    "country": "Inconnu",
    "latitude": None,
    "longitude": None,
    "targeted_machines": set()
})

print("Analyse des paquets réseau en cours...")

# Chargement du fichier PCAP
capture = pyshark.FileCapture(PCAP_FILE, use_json=True)

for packet in capture:
    try:
        total_packets += 1

        # Récupération des infos réseau
        ip_src = packet.ip.src
        ip_dst = packet.ip.dst
        proto = packet.highest_layer

        # Filtrage local ou Microsoft
        if is_microsoft_ip(ip_src) or is_microsoft_ip(ip_dst):
            continue

        # Incrémenter le compteur d'apparition pour ip_src
        ip_details[ip_src]["count"] += 1
        ip_details[ip_src]["targeted_machines"].add(ip_dst)

        # Ajout du protocole détecté (HTTP, KERBEROS, etc.)
        ip_details[ip_src]["protocols"].add(proto)

        # Analyse TCP
        if hasattr(packet, 'tcp'):
            # On incrémente le compteur global de ports
            port_counts[int(packet.tcp.srcport)] += 1
            port_counts[int(packet.tcp.dstport)] += 1

            # On stocke le port source dans ip_details
            ip_details[ip_src]["ports"].add(int(packet.tcp.srcport))

            # TCP Reset
            if packet.tcp.flags_reset == '1':
                tcp_resets += 1
                mitre_events[map_event("tcp_reset")] += 1

        # Analyse HTTP (téléchargement de .bin)
        if proto == "HTTP" and hasattr(packet, 'http'):
            if hasattr(packet.http, 'request_full_uri') and ".bin" in packet.http.request_full_uri:
                binary_downloads += 1
                mitre_events[map_event("binary_download")] += 1

        # Analyse Kerberos
        if proto == "KERBEROS" and hasattr(packet, 'kerberos'):
            if 'KRB5KDC_ERR_PREAUTH_REQUIRED' in packet.kerberos._all_fields:
                kerberos_failures += 1
                mitre_events[map_event("kerberos_fail")] += 1

    except AttributeError:
        # Certains paquets n'ont pas ip/tcp/http
        continue

for ip, data in ip_details.items():
    # Raison : "Apparue X fois"
    if data["count"] > 1:
        data["reasons"].append(f"Apparue {data['count']} fois")

    # Ports critiques
    sensitive_ports = {445, 3389}
    used_sens = data["ports"].intersection(sensitive_ports)
    if used_sens:
        data["reasons"].append(f"Port(s) sensible(s) utilisé(s): {used_sens}")

    # Métadonnées pays/lat/lon via GEO_DATA (exemple)
    if ip in GEO_DATA:
        data["country"] = GEO_DATA[ip]["country"]
        data["latitude"] = GEO_DATA[ip]["latitude"]
        data["longitude"] = GEO_DATA[ip]["longitude"]

    # Si IP externe => check réputation
    if not ip.startswith(LOCAL_NETWORK_PREFIX):
        if check_ip_reputation(ip):
            suspicious_ips.add(ip)
            data["reasons"].append("Réputation négative sur VirusTotal/AbuseIPDB")
        else:
            data["reasons"].append("Adresse IP externe")

# Analyse ports les plus utilisés (top 10)
top_port_counts = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
analysed_ports = [
    {"port": port, "count": count} for port, count in top_port_counts
]

# Conversion des sets en listes
for ip, data in ip_details.items():
    data["ports"] = sorted(list(data["ports"]))
    data["protocols"] = sorted(list(data["protocols"]))
    data["targeted_machines"] = sorted(list(data["targeted_machines"]))

# Création du dossier data
os.makedirs("data", exist_ok=True)

# Construction du rapport JSON final
rapport = {
    "date_generation": datetime.now().isoformat(),
    "fichier_pcap": PCAP_FILE,
    "statistiques": {
        "total_paquets": total_packets,
        "ips_analysees": len(ip_details),
        "echouements_kerberos": kerberos_failures,
        "telechargements_binaires_http": binary_downloads,
        "tcp_resets": tcp_resets,
        "ips_suspectes": list(suspicious_ips),
        "nombre_ips_suspectes": len(suspicious_ips)
    },
    "mitre_attacks": dict(mitre_events),
    "ports_analyse": analysed_ports,
    "ips": dict(ip_details),
    "configuration": {
        "reseau_local": LOCAL_NETWORK_PREFIX,
        "analyse_verbose": VERBOSE
    }
}

# Sauvegarde du JSON
rapport_path = os.path.join("data", "rapport_analyse.json")
with open(rapport_path, "w", encoding="utf-8") as f:
    json.dump(rapport, f, indent=4)

print("\n--- Rapport d'analyse ---")
print(f"Total de paquets : {total_packets}")
print(f"Nombre d'IPs analysées : {len(ip_details)}")
print(f"Échecs Kerberos : {kerberos_failures}")
print(f"Téléchargements binaires : {binary_downloads}")
print(f"TCP Resets : {tcp_resets}")
print(f"IPs suspectes : {len(suspicious_ips)}")
print(f"Top ports : {analysed_ports}")
print("\nRépartition MITRE ATT&CK :")
for category, count in mitre_events.items():
    print(f"- {category} : {count} événements")

print(f"\nAnalyse complète sauvegardée dans '{rapport_path}'")
