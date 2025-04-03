import requests

url = f"http://93.127.203.48:5000/pcap/submit"
PCAP_FILE = "logs/capture.pcap"  


def send_flag(info):

    data = {
        "user_id": "simon",
        "lines": [
            info[3],
            info[0],
            info[2],
            info[1]
        ]
    }

    try:
        response = requests.post(url, json=data, timeout=5)
        response.raise_for_status() 
        api_response = response.json()
        print("Réponse de l'API :", api_response)
        return api_response
    except requests.exceptions.RequestException as e:
        print("Erreur lors de l'envoi de la requête :", e)
        return None

