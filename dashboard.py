import streamlit as st
import pandas as pd
import json
import os
from analyse import download_pcap  # Importer uniquement la fonction de téléchargement

# Chemin du fichier JSON
JSON_FILE = "data/rapport_analyse.json"

# Charger les données du fichier JSON
def load_json_data():
    try:
        with open(JSON_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        st.error(f"Le fichier {JSON_FILE} est introuvable.")
        return None
    except json.JSONDecodeError:
        st.error(f"Erreur lors du chargement du fichier {JSON_FILE}.")
        return None

# Interface Streamlit
st.title("Dashboard d'Analyse des Données")

# Bouton pour télécharger le fichier .pcap
if st.button("Télécharger le fichier .pcap"):
    if download_pcap():
        st.success("Fichier .pcap téléchargé avec succès.")

# Bouton pour effectuer une nouvelle analyse
if st.button("Refaire une analyse"):
    result = os.system("python analyse.py")  # Exécuter le script analyse.py
    if result == 0:
        st.success("Nouvelle analyse effectuée avec succès.")
    else:
        st.error("Erreur lors de l'exécution de l'analyse.")

# Charger les données du fichier JSON
data = load_json_data()
if data:
    # Afficher les statistiques générales
    st.subheader("Statistiques Générales")
    stats = data.get("statistiques", {})
    if stats:
        st.write(f"Total de paquets : {stats.get('total_paquets', 0)}")
        st.write(f"Nombre d'IPs uniques : {stats.get('nombre_ips_uniques', 0)}")
        st.write(f"Échecs Kerberos : {stats.get('echouements_kerberos', 0)}")
        st.write(f"Téléchargements binaires HTTP : {stats.get('telechargements_binaire_http', 0)}")
        st.write(f"TCP Resets : {stats.get('tcp_resets', 0)}")
        st.write(f"Nombre d'IPs suspectes : {stats.get('nombre_ips_suspectes', 0)}")

    # Afficher les IPs uniques
    st.subheader("Liste des IPs Uniques")
    unique_ips = stats.get("ips_uniques", [])
    if unique_ips:
        st.dataframe(pd.DataFrame({"IPs Uniques": unique_ips}))
    else:
        st.info("Aucune IP unique disponible.")

    # Afficher les IPs suspectes
    st.subheader("Liste des IPs Suspectes")
    suspicious_ips = stats.get("ips_suspectes", [])
    if suspicious_ips:
        st.dataframe(pd.DataFrame({"IPs Suspectes": suspicious_ips}))
    else:
        st.info("Aucune IP suspecte détectée.")

    # Graphique : Analyse des ports
    st.subheader("Analyse des Ports")
    ports_analysis = data.get("ports_analyse", [])
    if ports_analysis:
        df_ports = pd.DataFrame(ports_analysis)
        st.dataframe(df_ports)
        if "port" in df_ports.columns and "count" in df_ports.columns:
            st.bar_chart(df_ports.set_index("port")["count"])
    else:
        st.info("Aucune donnée d'analyse des ports disponible.")
