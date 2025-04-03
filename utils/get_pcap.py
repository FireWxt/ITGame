import requests
import time
import os
import threading
import pyshark
import asyncio

def get_pcap(): 
    url = f"http://93.127.203.48:5000/pcap/latest"
    response = requests.get(url)
    if response.status_code == 200:
        file_path = os.path.join("logs/", "capture.pcap")
        with open(file_path, "wb") as f:
            f.write(response.content)
        print(f"[PCAP] Fichier PCAP enregistré sous {file_path}")
        capture = pyshark.FileCapture(file_path, use_json=True)
        return capture
    else:
        raise Exception(f"[PCAP] Erreur lors de la récupération du fichier PCAP : {response.status_code}")
    


def pcap_listener(interval=1800):
    """
    Fonction pour écouter les paquets sur le réseau et les enregistrer dans un fichier PCAP.
    """

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    while True:
        get_pcap()
        time.sleep(interval)
