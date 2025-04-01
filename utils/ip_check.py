import requests
import os
import time
from dotenv import load_dotenv

load_dotenv()

API_KEY_ABUSEIPDB = os.getenv('ABUSEIPDB_API_KEY')
API_KEY_VT = os.getenv('VT_API_KEY')

def check_ip_abuse(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {'Key': API_KEY_ABUSEIPDB, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    response = requests.get(url, headers=headers, params=params)
    # print(response.status_code)
    if response.status_code == 200:
        score = response.json()['data']['abuseConfidenceScore']
        return score > 50, score
    return False, 0

def check_ip_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"X-Apikey": API_KEY_VT}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        result = (stats['malicious'] > 0, stats['malicious'])
    else:
        result = (False, 0)
    time.sleep(15)  # Delay to ensure no more than 4 requests per minute
    return result
