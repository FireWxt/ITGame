import requests

def get_pcap(): 
    url = f"http://93.127.203.48:5000/pcap/latest"
    response = requests.get(url)
    contenue = response.content
    if response.status_code == 200:
        with open('logs/capture.pcap', 'wb') as f:
            f.write(contenue)
        print("Fichier PCAP téléchargé avec succès.")
    else:
        print("Erreur lors du téléchargement du fichier PCAP.")
