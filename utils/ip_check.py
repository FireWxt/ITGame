import requests
import os
from dotenv import load_dotenv
import time

# Chargement des clés API depuis le fichier .env
load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

# Configuration des URL d’API
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

def check_ip_abuseipdb(ip):
    """
    Vérifie la réputation d'une adresse IP via AbuseIPDB.
    Retourne True si le score de confiance en abus est supérieur à 50.
    """
    print(f"Using ABUSEIPDB API key: {ABUSEIPDB_API_KEY}")
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }
    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
        response.raise_for_status()
        score = response.json()['data']['abuseConfidenceScore']
        return score > 50
    except Exception:
        return False

def check_ip_virustotal(ip):
    """
    Vérifie la réputation d'une adresse IP via VirusTotal.
    Retourne True si des détections malveillantes sont signalées.
    """
    print(f"Using VT API key: {VT_API_KEY}")  # Debug: should print your key, not None

    headers = {
        'Accept': 'application/json',
        "X-Apikey": VT_API_KEY
    }
    result = False
    try:
        response = requests.get(VIRUSTOTAL_URL + ip, headers=headers)
        response.raise_for_status()
        data = response.json()
        malicious = data['data']['attributes']['last_analysis_stats']['malicious']
        result = malicious > 0
    except Exception as e:
        result = False
    time.sleep(15)
    return result


def check_ip_reputation(ip):
    """
    Combine les résultats de VirusTotal et AbuseIPDB.
    Retourne True si l'une des deux plateformes signale un comportement suspect.
    """
    return check_ip_abuseipdb(ip) or check_ip_virustotal(ip)
