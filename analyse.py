import pyshark
import os
import requests
from collections import defaultdict
from dotenv import load_dotenv
from datetime import datetime
from utils.get_pcap import get_pcap
from utils.mapping import get_mitre_signatures
from utils.ip_check import check_ip_abuse, check_ip_virustotal

# Charger les variables d’environnement (.env)
load_dotenv()
API_KEY = os.getenv('ABUSEIPDB_API_KEY')
API_KEY_VT = os.getenv('VT_API_KEY')

get_pcap()

# Fichier à analyser
PCAP_FILE = './logs/capture.pcap'
LOCAL_NETWORK = "172."
VERBOSE = False

# Initialisation des stats
stats = {
    'total_packets': 0,
    'unique_ips': set(),
    'kerberos_fails': 0,
    'http_downloads': 0,
    'tcp_resets': 0,
    'ip_alerts': {},  # ip: {abuse_score, vt_score}
    'mitre_mapping': defaultdict(list),  # cat: [(time, ip_src, proto)]
}

print("Début de l'analyse...\n")

# Récupération des règles MITRE
signatures = get_mitre_signatures()

# Analyse des paquets
capture = pyshark.FileCapture(PCAP_FILE, use_json=True, include_raw=True)



for packet in capture:
    query_name = ''
    stats['total_packets'] += 1
    try:
        ip_src = packet.ip.src
        ip_dst = packet.ip.dst
        proto = packet.highest_layer
        time = packet.sniff_time
        packet_str = packet.get_raw_packet()

        stats['unique_ips'].update([ip_src, ip_dst])

        if VERBOSE:
            print(f"[{time}] {proto} | {ip_src} → {ip_dst}")

        # Détection Kerberos
        if proto == "KERBEROS" and hasattr(packet, 'kerberos'):
            try:
                if 'KRB5KDC_ERR_PREAUTH_REQUIRED' in packet.kerberos._all_fields:
                    stats['kerberos_fails'] += 1
                    stats['mitre_mapping']["Credential Access"].append((time, ip_src, proto))
                    print("Échec d'authentification Kerberos détecté")
            except:
                continue

        # Téléchargement binaire HTTP
        if proto == "HTTP" and hasattr(packet.http, 'request_full_uri') and ".bin" in packet.http.request_full_uri:
            stats['http_downloads'] += 1
            stats['mitre_mapping']["Initial Access"].append((time, ip_src, proto))
            print("Téléchargement de fichier binaire détecté :", packet.http.request_full_uri)

        # TCP Reset
        if hasattr(packet, 'tcp') and packet.tcp.flags_reset == '1':
            stats['tcp_resets'] += 1
            stats['mitre_mapping']["Defense Evasion"].append((time, ip_src, proto))
            print("TCP Reset détecté")
        # Détection DNS suspectes
        if proto == "DNS" and hasattr(packet, 'dns'):
            query_name = packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else ''
    
        
        # Vérification de la longueur de la requête DNS
        if query_name:
            if len(query_name) > 30 and any(ext in query_name for ext in ['.xyz', '.top', '.tk']):
                stats['mitre_mapping']["Command and Control"].append((time, ip_src, proto))
            print(f"Requête DNS suspecte vers : {query_name}")

        # Autres signatures MITRE ATT&CK
        for tactic, rules in signatures.items():
            for rule in rules:
                try:
                    if rule(packet_str):
                        stats['mitre_mapping'][tactic].append((time, ip_src, proto))
                except:
                    continue

    except AttributeError:
        continue

# Vérification des IPs via AbuseIPDB + VirusTotal
print("\nVérification des adresses IP externes...\n")
for ip in stats['unique_ips']:
    if not ip.startswith(LOCAL_NETWORK):
        abuse_flagged, abuse_score = check_ip_abuse(ip)
        vt_flagged, vt_score = check_ip_virustotal(ip)
        if abuse_flagged or vt_flagged:
            stats['ip_alerts'][ip] = {
                'abuse_score': abuse_score,
                'vt_score': vt_score
            }
            print(f"IP suspecte : {ip} | Abuse: {abuse_score}, VirusTotal: {vt_score}")

print("\n[DEBUG] Contenu final de stats['ip_alerts']:")
print(stats['ip_alerts'])

# Rapport console
print("\nRapport Synthétique")
print(f"Total de paquets analysés : {stats['total_packets']}")
print(f"IPs uniques : {len(stats['unique_ips'])}")
print(f"Échecs Kerberos : {stats['kerberos_fails']}")
print(f"Téléchargements binaires HTTP : {stats['http_downloads']}")
print(f"TCP Resets : {stats['tcp_resets']}")
print(f"IPs suspectes : {len(stats['ip_alerts'])}")
for ip, alert in stats['ip_alerts'].items():
    print(f"  - {ip} : Abuse = {alert['abuse_score']}, VT = {alert['vt_score']}")

print("\nMITRE ATT&CK - Détails :")
for tactic, events in stats['mitre_mapping'].items():
    print(f" - {tactic} : {len(events)} événements")

print("\nAnalyse terminée.")

# Génération rapport Markdown
def generate_report(stats, filename="data/rapport_analyse.md"):
    with open(filename, "w", encoding='utf-8') as f:
        f.write(f"# Rapport d'analyse - {datetime.now().strftime('%d/%m/%Y %H:%M')}\n\n")
        f.write(f"- Total de paquets : {stats['total_packets']}\n")
        f.write(f"- IPs uniques : {len(stats['unique_ips'])}\n")
        f.write(f"- Échecs Kerberos : {stats['kerberos_fails']}\n")
        f.write(f"- Téléchargements binaires : {stats['http_downloads']}\n")
        f.write(f"- TCP Resets : {stats['tcp_resets']}\n\n")

        f.write("## MITRE ATT&CK Mapping\n")
        for cat, entries in stats['mitre_mapping'].items():
            f.write(f"### {cat} ({len(entries)})\n")
            for e in entries:
                f.write(f"- [{e[0]}] {e[1]} via {e[2]}\n")
        f.write("\n")

        f.write("## IPs suspectes\n")
        for ip, scores in stats['ip_alerts'].items():
            f.write(f"- {ip} : Abuse = {scores['abuse_score']}, VT = {scores['vt_score']}\n")
        f.write(f"### Nombre total d'IP suspectes : {len(stats['ip_alerts'])}\n\n")


# Enregistrer le rapport
generate_report(stats)
print("Rapport Markdown généré dans data/rapport_analyse.md")
