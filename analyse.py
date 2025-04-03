import pyshark
import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv
from collections import defaultdict

# Import des modules internes (selon votre structure de projet)
from utils.get_pcap import get_pcap
from utils.MicrosoftFilter import is_microsoft_ip
from utils.ip_check import check_ip_reputation
from utils.mitre_mapping import map_event
from utils.PortAnalyse import analyse_ports
from utils.mitre_rules import apply_mitre_rules

# Chargement des variables d'environnement (clés API, etc.)
load_dotenv()

# Chemins et constantes
PCAP_FILE = "logs/capture.pcap"
LOCAL_NETWORK_PREFIX = "172."
VERBOSE = False

# API publique pour la géolocalisation
GEOLOCATION_API_URL = "https://ipapi.co"

# Structure initiale de collecte des statistiques
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
        "region": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "score": 0,
        "targeted_machines": set()
    })
}

def fetch_geo_data(ip):
    """
    Récupère les informations de géolocalisation pour une IP via ipapi.co.
    Retourne un dictionnaire (country, region, city, latitude, longitude).
    """
    try:
        url = f"{GEOLOCATION_API_URL}/{ip}/json/"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            return {
                "country": data.get("country_name", "Inconnu"),
                "region": data.get("region"),
                "city": data.get("city"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude")
            }
    except requests.RequestException:
        # En cas d'erreur réseau / timeout, on ignore
        pass
    return None

def compute_ip_score(details):
    """
    Calcule un score de risque basique pour une IP.
    Par exemple :
     - +5 si "Réputation négative" est trouvée dans les raisons
     - +2 si la machine utilise des ports sensibles (445, 3389)
     - +1 pour chaque tranche de 100 paquets au-dessus de 100.
    """
    score = 0

    # Réputation négative
    if any("Réputation négative" in reason for reason in details["reasons"]):
        score += 5

    # Ports sensibles
    sensitive_ports = {445, 3389}
    if len(details["ports"].intersection(sensitive_ports)) > 0:
        score += 2

    # Nombre de paquets au-delà de 100
    overflow = max(0, details["count"] - 100)
    score += overflow // 100

    return score

def main():
    # Optionnel : téléchargement automatique du PCAP depuis un serveur / API
    # get_pcap()

    if not os.path.exists(PCAP_FILE):
        print(f"[Erreur] Fichier PCAP introuvable : {PCAP_FILE}")
        return

    print("Analyse des paquets réseau en cours...")

    # Chargement du PCAP
    capture = pyshark.FileCapture(PCAP_FILE, use_json=True, include_raw=True)

    # Parcours des paquets
    for packet in capture:
        try:
            stats["total_packets"] += 1

            # Récupération des champs IP
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            proto = packet.highest_layer

            # On ignore le trafic Microsoft
            if is_microsoft_ip(ip_src) or is_microsoft_ip(ip_dst):
                continue

            # Infos sur l'IP source
            details = stats["ip_details"][ip_src]
            details["count"] += 1
            details["targeted_machines"].add(ip_dst)
            details["protocols"].add(proto)

            # Gestion TCP
            if hasattr(packet, "tcp"):
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)

                stats["port_counts"][src_port] += 1
                stats["port_counts"][dst_port] += 1
                details["ports"].add(src_port)

                if packet.tcp.flags_reset == "1":
                    stats["tcp_resets"] += 1
                    stats["mitre_events"][map_event("tcp_reset")] += 1

            # Application des règles MITRE personnalisées
            dst_port = int(packet.tcp.dstport) if hasattr(packet, "tcp") else None
            apply_mitre_rules(packet, proto, ip_src, ip_dst, dst_port, stats, details, LOCAL_NETWORK_PREFIX)

        except AttributeError:
            # Certains paquets n'ont pas les couches IP ou TCP
            continue

    # Post-traitement sur chaque IP
    for ip, data in stats["ip_details"].items():
        # Marqueur d'apparition
        if data["count"] > 1:
            data["reasons"].append(f"Apparue {data['count']} fois")

        # Géolocalisation si IP non locale
        if not ip.startswith(LOCAL_NETWORK_PREFIX):
            geo_info = fetch_geo_data(ip)
            if geo_info:
                data["country"] = geo_info["country"]
                data["region"] = geo_info["region"]
                data["city"] = geo_info["city"]
                data["latitude"] = geo_info["latitude"]
                data["longitude"] = geo_info["longitude"]

        # Ports sensibles
        sensitive_ports = {445, 3389}
        if data["ports"].intersection(sensitive_ports):
            data["reasons"].append(f"Port(s) sensible(s) utilisé(s): {data['ports'].intersection(sensitive_ports)}")

        # Réputation
        if not ip.startswith(LOCAL_NETWORK_PREFIX):
            if check_ip_reputation(ip):
                stats["suspicious_ips"].add(ip)
                data["reasons"].append("Réputation négative sur VirusTotal/AbuseIPDB")
            else:
                data["reasons"].append("Adresse IP externe")

        # Calcul du score de risque
        data["score"] = compute_ip_score(data)

        # Tri / conversion en listes pour le rapport JSON
        data["ports"] = sorted(list(data["ports"]))
        data["protocols"] = sorted(list(data["protocols"]))
        data["targeted_machines"] = sorted(list(data["targeted_machines"]))

    # Tri / liste des ports
    top_ports_sorted = sorted(stats["port_counts"].items(), key=lambda x: x[1], reverse=True)
    analysed_ports = [{"port": port, "count": count} for port, count in top_ports_sorted]

    # Machines potentiellement infectées (ciblées par IP suspectes)
    infected_machines = set()
    for ip_suspecte in stats["suspicious_ips"]:
        if ip_suspecte in stats["ip_details"]:
            for target in stats["ip_details"][ip_suspecte]["targeted_machines"]:
                if target.startswith(LOCAL_NETWORK_PREFIX):
                    infected_machines.add(target)

    # Construction du rapport final
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

    # Sauvegarde du rapport en JSON
    os.makedirs("data", exist_ok=True)
    rapport_path = os.path.join("data", "rapport_analyse.json")
    with open(rapport_path, "w", encoding="utf-8") as f:
        json.dump(rapport, f, indent=4)

    # Affichage console synthétique
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


if __name__ == "__main__":
    main()
