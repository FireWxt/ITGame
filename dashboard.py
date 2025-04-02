import streamlit as st
import pandas as pd
import json
import os
from analyse import download_pcap

# Configuration de la page
st.set_page_config(page_title="Datalitics", layout="wide")

# Chemin du fichier JSON
JSON_FILE = "data/rapport_analyse.json"

# Charger les données du fichier JSON
def load_json_data():
    try:
        with open(JSON_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except (FileNotFoundError, json.JSONDecodeError):
        return None

# Barre latérale (Sidebar)
st.sidebar.image("assets/logo.png", width=150)
st.sidebar.header("Datalitics")
st.sidebar.button("Import PCAP")
st.sidebar.markdown("---")
st.sidebar.button("Overview")
st.sidebar.button("MITRE ATT&CK")
st.sidebar.button("Suspicious IPs")
st.sidebar.button("Report")

# Contenu principal
st.title("Network Analysis – MITRE ATT&CK")

# Section Import PCAP avec boutons
st.subheader("Import PCAP")
col1, col2 = st.columns([3, 1])
with col1:
    st.file_uploader("Choose a PCAP file", type=["pcap"])
with col2:
    if st.button("Browse..."):
        st.success("PCAP file selected.")

# Charger les données
data = load_json_data()
if data:
    stats = data.get("statistiques", {})
    
    # Affichage des statistiques
    st.subheader("Statistiques Générales")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Packets", stats.get("total_paquets", 0))
    col2.metric("Unique IPs", stats.get("nombre_ips_uniques", 0))
    col3.metric("Kerberos 230", stats.get("echouements_kerberos", 0))
    col4.metric("HTTP Download", stats.get("telechargements_binaire_http", 0))
    
    # MITRE ATT&CK Tactics
    st.subheader("MITRE ATT&CK Tactics")
    st.markdown("- **Credential Access**\n- **Command and Control**\n- **Discovery**\n- **Defense Evasion**\n- **Execution**")
    
    # Détection des événements
    st.subheader("Detected Events")
    detected_events = data.get("detected_events", [])
    if detected_events:
        df_events = pd.DataFrame(detected_events)
        st.dataframe(df_events)
    else:
        st.info("No detected events.")
    
    # Liste des IPs suspectes
    st.subheader("Suspicious IPs")
    suspicious_ips = stats.get("ips_suspectes", [])
    if suspicious_ips:
        df_suspicious = pd.DataFrame(suspicious_ips, columns=["IP Address", "AbuseIPDB Score"])
        st.dataframe(df_suspicious)
    else:
        st.info("No suspicious IPs detected.")

    # Rapport Markdown
    st.subheader("Markdown Report")
    st.markdown("### 🛡️ Network Analysis Report\n- Analyzed PCAP file and identified suspicious activity")
    st.button("Download Report")
