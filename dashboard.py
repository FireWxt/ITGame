import streamlit as st
import pandas as pd
import json
import os

# Configuration de la page
st.set_page_config(page_title="Datalitics - Analyse Réseau", layout="wide")

# Chargement des données JSON
def load_json_data():
    try:
        with open("data/rapport_analyse.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

# Sidebar
st.sidebar.image("assets/logo.png", width=150)
st.sidebar.title("Datalitics")
st.sidebar.markdown("---")
st.sidebar.subheader("Navigation")
st.sidebar.button("Importer un PCAP")
st.sidebar.button("Vue d'ensemble")
st.sidebar.button("MITRE ATT&CK")
st.sidebar.button("IPs suspectes")
st.sidebar.button("Rapport")

# Titre principal
st.markdown("""
    <h1 style='text-align: center; color: #1E90FF;'>Analyse du trafic réseau - MITRE ATT&CK</h1>
""", unsafe_allow_html=True)

# Import PCAP
st.subheader("Importer un fichier PCAP")
col1, col2 = st.columns([3, 1])
with col1:
    st.file_uploader("Choisissez un fichier PCAP", type=["pcap"])
with col2:
    if st.button("Parcourir..."):
        st.success("Fichier PCAP sélectionné.")

# Chargement du rapport
rapport = load_json_data()
if rapport:
    stats = rapport.get("statistiques", {})

    st.subheader("Statistiques Générales")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total de paquets", stats.get("total_paquets", 0))
    col2.metric("IPs uniques", len(rapport.get("ips", {})))
    col3.metric("Echecs Kerberos", stats.get("echouements_kerberos", 0))
    col4.metric("Fichiers .bin", stats.get("telechargements_binaires_http", 0))

    st.subheader("MITRE ATT&CK - Tactiques observées")
    for tactic, count in rapport.get("mitre_attacks", {}).items():
        st.markdown(f"- **{tactic}** : {count} événements")

    st.subheader("IPs suspectes")
    suspicious_ips = stats.get("ips_suspectes", [])
    if suspicious_ips:
        df_ips = pd.DataFrame(suspicious_ips, columns=["Adresse IP"])
        st.dataframe(df_ips, use_container_width=True)
    else:
        st.success("Aucune IP suspecte détectée.")

    st.subheader("Machines locales potentiellement infectées")
    infected = stats.get("machines_possiblement_infectees", [])
    if infected:
        st.write("IPs internes ciblées :")
        st.code("\n".join(infected))
    else:
        st.success("Aucune machine locale ciblée.")

    st.subheader("Rapport final")
    st.markdown("""
    ### Synthèse de l'analyse :
    - Fichier PCAP analysé
    - IPs suspectes identifiées
    - MITRE ATT&CK mapping
    - Ports sensibles utilisés
    """)

    with open("data/rapport_analyse.json", "rb") as f:
        st.download_button("Télécharger le rapport JSON", f, file_name="rapport_analyse.json")
