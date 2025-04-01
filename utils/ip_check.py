import requests
import os

API_KEY_ABUSEIPDB = os.getenv('ABUSEIPDB_API_KEY')
API_KEY_VT = os.getenv('VT_API_KEY')

def check_ip_abuse(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {'Key': API_KEY_ABUSEIPDB, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        score = response.json()['data']['abuseConfidenceScore']
        return score > 50, score
    return False, 0

def check_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY_VT}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        stats = response.json()['data']['attributes']['last_analysis_stats']
        return stats['malicious'] > 0, stats['malicious']
    return False, 0
