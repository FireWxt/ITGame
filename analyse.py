import pyshark
import requests
from collections import defaultdict
from datetime import datetime
import os
API_KEY = os.getenv('ABUSEIPDB_API_KEY')

capture = pyshark.FileCapture('logs/capture.pcap')
print("Début de l’analyse...\n")

# Statistiques globales
stats = {
    'total_packets': 0,
    'unique_ips': set(),
    'kerberos_failures': 0,
    'http_downloads': 0,
    'tcp_resets': 0,
    'ip_alerts': defaultdict(list),
    'mitre_mapping': defaultdict(list),
}

# Vérification AbuseIPDB
def check_ip_abuse(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {'Key': API_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()['data']
        if data['abuseConfidenceScore'] > 50:
            return True, data['abuseConfidenceScore']
    return False, 0

# Mapping MITRE ATT&CK simplifié
def map_to_mitre(proto, packet_str):
    if "KERBEROS" in proto and "KRB5KDC_ERR_PREAUTH_REQUIRED" in packet_str:
        return "Credential Access"
    if "HTTP" in proto and ".bin" in packet_str:
        return "Initial Access"
    if "flags_reset" in packet_str:
        return "Defense Evasion"
    return None

# Analyse des paquets
for packet in capture:
    stats['total_packets'] += 1
    try:
        ip_src = packet.ip.src
        ip_dst = packet.ip.dst
        proto = packet.highest_layer
        time = packet.sniff_time
        packet_str = str(packet)

        stats['unique_ips'].update([ip_src, ip_dst])
        
        print(f"[{time}] {proto} | {ip_src} → {ip_dst}")

        # KERBEROS
        if proto == "KERBEROS" and "KRB5KDC_ERR_PREAUTH_REQUIRED" in packet_str:
            stats['kerberos_failures'] += 1
            print("❌ Échec Kerberos détecté")

        # HTTP
        if proto == "HTTP" and hasattr(packet.http, 'request_full_uri') and ".bin" in packet.http.request_full_uri:
            stats['http_downloads'] += 1
            print("⚠️ Téléchargement binaire détecté :", packet.http.request_full_uri)

        # TCP Reset
        if hasattr(packet, 'tcp') and packet.tcp.flags_reset == '1':
            stats['tcp_resets'] += 1
            print("🔴 TCP Reset détecté")

        # Détection MITRE ATT&CK
        mitre_cat = map_to_mitre(proto, packet_str)
        if mitre_cat:
            stats['mitre_mapping'][mitre_cat].append((time, ip_src, proto))
        
    except AttributeError:
        continue

# Vérification des IPs suspectes
print("\nVérification des adresses IP sur AbuseIPDB...\n")
for ip in stats['unique_ips']:
    try:
        flagged, score = check_ip_abuse(ip)
        if flagged:
            stats['ip_alerts'][ip] = score
            print(f"🚨 IP suspecte : {ip} | Score : {score}")
    except Exception as e:
        print(f"Erreur vérification IP {ip} : {e}")

# Rapport final
print("\n🧾 Rapport Synthétique")
print(f"📦 Total de paquets analysés : {stats['total_packets']}")
print(f"🌐 IPs uniques : {len(stats['unique_ips'])}")
print(f"🔐 Échecs Kerberos : {stats['kerberos_failures']}")
print(f"📥 Téléchargements binaires HTTP : {stats['http_downloads']}")
print(f"🔁 TCP Resets : {stats['tcp_resets']}")
print(f"🛑 IPs suspectes : {len(stats['ip_alerts'])}")

print("\n📚 MITRE ATT&CK - Détails :")
for category, entries in stats['mitre_mapping'].items():
    print(f" - {category} : {len(entries)} événements")

print("\nAnalyse terminée.")
