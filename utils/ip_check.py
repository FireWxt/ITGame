import requests
import os
from dotenv import load_dotenv
import time

# On charge les variables d'env (les clés API)
load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
API_KEY_VT = os.getenv("API_KEY_VT")

# URL des APIs
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

def get_abuseipdb_details(ip):
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY  
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }

    details = {
        "ipAddress": ip,
        "abuseConfidenceScore": 0,
        "countryCode": None,
        "isp": None,
        "domain": None,
        "usageType": None,
        "isPublic": None,
        "isWhitelisted": None,
        "lastReportedAt": None
    }
    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
        response.raise_for_status()
        data = response.json().get("data", {})

        details["abuseConfidenceScore"] = data.get("abuseConfidenceScore", 0)
        details["countryCode"] = data.get("countryCode")
        details["isp"] = data.get("isp")
        details["domain"] = data.get("domain")
        details["usageType"] = data.get("usageType")
        details["isPublic"] = data.get("isPublic")
        details["isWhitelisted"] = data.get("isWhitelisted")
        details["lastReportedAt"] = data.get("lastReportedAt")

    except Exception as e:
        print(f"Erreur dans get_abuseipdb_details pour {ip}: {e}")

    return details

def get_virustotal_details(ip):
    """
    Récupère des infos depuis VirusTotal :
      malicious, harmless, suspicious, country, asn, etc.
    """
    print(f"Using VT API key: {API_KEY_VT}") 

    headers = {
        "x-apikey": API_KEY_VT
    }
    details = {
        "malicious": 0,
        "harmless": 0,
        "suspicious": 0,
        "country": None,
        "asn": None,
        "as_owner": None,
        "network": None
    }
    result = False
    try:
        response = requests.get(VIRUSTOTAL_URL + ip, headers=headers)
        response.raise_for_status()
        data = response.json()["data"]["attributes"]

        stats = data.get("last_analysis_stats", {})
        details["malicious"] = stats.get("malicious", 0)
        details["harmless"] = stats.get("harmless", 0)
        details["suspicious"] = stats.get("suspicious", 0)

        details["country"] = data.get("country")
        details["asn"] = data.get("asn")
        details["as_owner"] = data.get("as_owner")
        details["network"] = data.get("network")

    except Exception as e:
        print(f"Erreur dans get_virustotal_details pour {ip}: {e}")

    return details

def check_ip_details(ip):
    """
    Combine les détails de AbuseIPDB et VirusTotal en un seul dictionnaire.
    """
    abuse_info = get_abuseipdb_details(ip)
    vt_info = get_virustotal_details(ip)

    combined = {
        "ip": ip,
        "abuseConfidenceScore": abuse_info.get("abuseConfidenceScore", 0),
        "countryCodeAbuse": abuse_info.get("countryCode"),
        "ispAbuse": abuse_info.get("isp"),
        "domainAbuse": abuse_info.get("domain"),
        "usageTypeAbuse": abuse_info.get("usageType"),
        "lastReportedAtAbuse": abuse_info.get("lastReportedAt"),

        "vtMalicious": vt_info["malicious"],
        "vtHarmless": vt_info["harmless"],
        "vtSuspicious": vt_info["suspicious"],
        "vtCountry": vt_info["country"],
        "vtASN": vt_info["asn"],
        "vtASOwner": vt_info["as_owner"],
        "vtNetwork": vt_info["network"]
    }
    return combined

def check_ip_abuseipdb(ip):
    """
    Vérifie rapidement la réputation AbuseIPDB 
    """
    info = get_abuseipdb_details(ip)
    return info["abuseConfidenceScore"] > 50

def check_ip_virustotal(ip):
    """
    Vérifie rapidement la réputation sur VirusTotal 
    """
    info = get_virustotal_details(ip)
    return info["malicious"] > 0

def check_ip_reputation(ip):
    """
    Renvoie True si l'IP est suspecte selon l'une des deux (AbuseIPDB ou VirusTotal).
    """
    return check_ip_abuseipdb(ip) or check_ip_virustotal(ip)
