import requests

url = f"http://93.127.203.48:5000/pcap/submit"
PCAP_FILE = "logs/capture.pcap"  # Chemin vers le fichier PCAP à analyser


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
        response = requests.post(url, json=data)
        response.raise_for_status()  # Vérifie que la requête s'est bien passée
        print("Réponse de l'API :", response.json())
        apiresponse = response.json()
        return apiresponse
    except requests.exceptions.RequestException as e:
        print("Erreur lors de l'envoi de la requête :", e)

