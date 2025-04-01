import pyshark
import os
import json
import requests
import asyncio  # Import asyncio for event loop management
import hashlib
from datetime import datetime
from dotenv import load_dotenv
from collections import defaultdict
from utils.MicrosoftFilter import is_microsoft_ip
from utils.ip_check import check_ip_reputation
from utils.mitre_mapping import map_event
from utils.PortAnalyse import analyse_ports

# Chemins des fichiers
PCAP_URL = os.getenv('ADRESSE_PCAP')
PCAP_FILE = "logs/capture.pcap"
JSON_FILE = "data/rapport_analyse.json"

# Télécharger le fichier .pcap
def download_pcap():
    try:
        response = requests.get(PCAP_URL, stream=True)
        if response.status_code == 200:
            with open(PCAP_FILE, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            return True
        else:
            print(f"Erreur lors du téléchargement : {response.status_code}")
            return False
    except Exception as e:
        print(f"Erreur lors du téléchargement : {e}")
        return False

# Analyse des paquets réseau
def analyze_pcap_file(pcap_file):
    # Ensure an event loop is available in the current thread
    if not asyncio.get_event_loop_policy().get_event_loop().is_running():
        asyncio.set_event_loop(asyncio.new_event_loop())

    capture = pyshark.FileCapture(pcap_file, use_json=True)
    total_packets = 0
    unique_ips = set()
    suspicious_ips = []
    kerberos_failures = 0
    binary_downloads = 0
    tcp_resets = 0
    mitre_events = defaultdict(int)
    port_counts = defaultdict(int)

    for packet in capture:
        try:
            total_packets += 1

            # Récupération des informations réseau
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            proto = packet.highest_layer
            time = packet.sniff_time

            # Filtrage des IPs locales ou Microsoft
            if is_microsoft_ip(ip_src) or is_microsoft_ip(ip_dst):
                continue

            unique_ips.update([ip_src, ip_dst])

            # Analyse TCP
            if hasattr(packet, 'tcp'):
                port_counts[int(packet.tcp.srcport)] += 1
                port_counts[int(packet.tcp.dstport)] += 1

                if packet.tcp.flags_reset == '1':
                    tcp_resets += 1
                    mitre_events[map_event("tcp_reset")] += 1

            # Analyse HTTP
            if proto == "HTTP" and hasattr(packet.http, 'request_full_uri'):
                if ".bin" in packet.http.request_full_uri:
                    binary_downloads += 1
                    mitre_events[map_event("binary_download")] += 1

            # Analyse Kerberos
            if proto == "KERBEROS" and hasattr(packet, 'kerberos'):
                if 'KRB5KDC_ERR_PREAUTH_REQUIRED' in packet.kerberos._all_fields:
                    kerberos_failures += 1
                    mitre_events[map_event("kerberos_fail")] += 1

        except AttributeError:
            continue

    # Vérification de la réputation des adresses IP
    for ip in unique_ips:
        if not ip.startswith(LOCAL_NETWORK_PREFIX):
            if check_ip_reputation(ip):
                suspicious_ips.append(ip)

    # Return analysis results
    return {
        "total_packets": total_packets,
        "unique_ips": unique_ips,
        "suspicious_ips": suspicious_ips,
        "kerberos_failures": kerberos_failures,
        "binary_downloads": binary_downloads,
        "tcp_resets": tcp_resets,
        "mitre_events": mitre_events,
        "port_counts": port_counts,
    }

# Chargement des variables d'environnement
load_dotenv()
LOCAL_NETWORK_PREFIX = "172."
VERBOSE = False  # Peut être utilisé pour afficher plus de logs
PCAP_URL = os.getenv('ADRESSE_PCAP')

# Main analysis logic
if __name__ == "__main__":
    print("Analyse des paquets réseau en cours...")

    # Appeler la fonction pour télécharger le fichier PCAP
    if download_pcap():
        print("Fichier .pcap téléchargé et prêt pour l'analyse.")
    else:
        print("Le fichier .pcap n'a pas été téléchargé. Utilisation du fichier existant.")

    # Perform the analysis
    results = analyze_pcap_file(PCAP_FILE)

    # Process and save the results
    total_packets = results["total_packets"]
    unique_ips = results["unique_ips"]
    suspicious_ips = results["suspicious_ips"]
    kerberos_failures = results["kerberos_failures"]
    binary_downloads = results["binary_downloads"]
    tcp_resets = results["tcp_resets"]
    mitre_events = results["mitre_events"]
    port_counts = results["port_counts"]

    # Affichage console
    print("\n--- Rapport d'analyse ---")
    print(f"Total de paquets : {total_packets}")
    print(f"Adresses IP uniques : {len(unique_ips)}")
    print(f"Échecs Kerberos : {kerberos_failures}")
    print(f"Téléchargements binaires : {binary_downloads}")
    print(f"TCP Resets : {tcp_resets}")
    print(f"IP suspectes détectées : {len(suspicious_ips)}")

    print("\nRépartition MITRE ATT&CK :")
    for category, count in mitre_events.items():
        print(f"{category} : {count} événements")

    # Analyse des ports les plus utilisés
    analysed_ports = analyse_ports(port_counts)
    # Crée le dossier "data" s'il n'existe pas
    os.makedirs("data", exist_ok=True)

    # Top des ports analysés (exemple : les 10 plus fréquents)
    top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    analysed_ports = [
        {"port": port, "count": count} for port, count in top_ports
    ]

    # Construction du rapport
    rapport = {
        "date_generation": datetime.now().isoformat(),
        "fichier_pcap": PCAP_FILE,
        "statistiques": {
            "total_paquets": total_packets,
            "ips_uniques": list(unique_ips),
            "nombre_ips_uniques": len(unique_ips),
            "echouements_kerberos": kerberos_failures,
            "telechargements_binaire_http": binary_downloads,
            "tcp_resets": tcp_resets,
            "ips_suspectes": suspicious_ips,
            "nombre_ips_suspectes": len(suspicious_ips)
        },
        "mitre_attacks": dict(mitre_events),  
        "ports_analyse": analysed_ports, 
        "configuration": {
            "reseau_local": LOCAL_NETWORK_PREFIX,
            "analyse_verbose": False
        }
    }

    # Sauvegarde JSON
    rapport_path = os.path.join("data", "rapport_analyse.json")
    with open(rapport_path, "w", encoding="utf-8") as f:
        json.dump(rapport, f, indent=4)

    print(f"Analyse complète sauvegardée dans '{rapport_path}'")

