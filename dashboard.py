import streamlit as st
import pandas as pd
import pydeck as pdk
import json
import subprocess
import os

# Configuration de la page
st.set_page_config(
    page_title="DATALYTICS",
    layout="wide"
)

def lancer_analyse():
    """
    Lance le script analyse.py via subprocess.
    Affiche un message de réussite ou d'erreur selon le résultat.
    """
    with st.spinner("Analyse en cours..."):
        result = subprocess.run(
            ["python", "analyse.py"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            st.success("Analyse terminée avec succès.")
        else:
            st.error("Erreur lors de l’analyse.")
            st.code(result.stderr)

def charger_rapport():
    """
    Charge et retourne le contenu du fichier data/rapport_analyse.json.
    Retourne None si le fichier n'existe pas ou n'est pas valide.
    """
    chemin_rapport = "data/rapport_analyse.json"
    if not os.path.exists(chemin_rapport):
        return None
    try:
        with open(chemin_rapport, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return None

def calcul_score(details):
    """
    Calcule un score de risque (0-100) à partir de divers indicateurs :
    - Nombre de paquets
    - Présence de ports sensibles
    - Réputation négative
    - Nombre de 'reasons'
    """
    base_score = 0
    count = details["count"]
    nb_reasons = len(details["reasons"])

    # Critère : nombre de paquets
    if count > 2000:
        base_score += 30
    elif count > 500:
        base_score += 15
    elif count > 100:
        base_score += 5

    # Critère : présence de ports sensibles (445, 3389)
    sensitive_ports = {445, 3389}
    if len(sensitive_ports.intersection(details["ports"])) > 0:
        base_score += 20

    # Critère : réputation négative
    if any("Réputation négative" in reason for reason in details["reasons"]):
        base_score += 30

    # Critère : accumulation de raisons
    if nb_reasons > 20:
        base_score += 10
    elif nb_reasons > 5:
        base_score += 5

    # Score final borné à 100
    return min(base_score, 100)

# Titre principal
st.title("Analyse Réseau – Tableau de bord avancé (MITRE ATT&CK)")

# Bouton pour exécuter le script d'analyse
if st.button("Lancer une nouvelle analyse PCAP"):
    lancer_analyse()

# Chargement du rapport JSON
rapport = charger_rapport()
if not rapport:
    st.warning("Aucun rapport trouvé. Lancez l'analyse ou vérifiez 'data/rapport_analyse.json'.")
    st.stop()

# Raccourcis pour naviguer dans le rapport
stats = rapport.get("statistiques", {})
ips_data = rapport.get("ips", {})
mitre_data = rapport.get("mitre_attacks", {})
ports_analyse = rapport.get("ports_analyse", [])

# Construction d'une DataFrame avec un score de risque pour chaque IP
liste_ip = []
for ip, details in ips_data.items():
    score_risque = calcul_score(details)
    if score_risque > 70:
        label_risque = "Critique"
    elif score_risque > 40:
        label_risque = "Élevé"
    elif score_risque > 20:
        label_risque = "Moyen"
    else:
        label_risque = "Faible"

    liste_ip.append({
        "Adresse IP": ip,
        "Paquets": details["count"],
        "Nb Ports": len(details["ports"]),
        "Risque": label_risque,
        "Score": score_risque,
        "Pays": details.get("country", "Inconnu"),
        "Reasons": "; ".join(details["reasons"][:3])  # Affichage limité
    })

df_ips = pd.DataFrame(liste_ip).sort_values(by="Score", ascending=False)

# Création de plusieurs onglets
onglets = st.tabs(["Statistiques Générales", "Tactiques MITRE", "IPs Suspectes", "Analyse Comportementale", "Carte"])

with onglets[0]:
    st.subheader("Statistiques Générales")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Paquets", stats.get("total_paquets", 0))
    col2.metric("IPs Analysées", stats.get("ips_analysees", 0))
    col3.metric("Échecs Kerberos", stats.get("echouements_kerberos", 0))
    col4.metric("Téléchargements binaires", stats.get("telechargements_binaires_http", 0))

    st.subheader("IPs suspectes identifiées")
    suspicious_ips = stats.get("ips_suspectes", [])
    if suspicious_ips:
        st.write(f"Nombre d'IPs suspectes : {len(suspicious_ips)}")
        st.write(suspicious_ips)
    else:
        st.info("Aucune IP suspecte détectée.")

    st.subheader("Machines possiblement infectées")
    infected_machines = stats.get("machines_possiblement_infectees", [])
    if infected_machines:
        st.write("Liste des IP internes ciblées :")
        st.code("\n".join(infected_machines))
    else:
        st.success("Aucune machine locale ciblée.")

    st.subheader("Top 10 des ports")
    if ports_analyse:
        df_ports = pd.DataFrame(ports_analyse).head(10)
        st.bar_chart(df_ports.set_index("port")["count"])
    else:
        st.info("Aucun port analysé dans le rapport.")

with onglets[1]:
    st.subheader("Tactiques MITRE ATT&CK détectées")
    if mitre_data:
        df_mitre = pd.DataFrame(list(mitre_data.items()), columns=["Tactique", "Occurrences"])
        st.bar_chart(df_mitre.set_index("Tactique")["Occurrences"])
        st.dataframe(df_mitre)
    else:
        st.info("Aucune tactique MITRE détectée.")

with onglets[2]:
    st.subheader("Détails IPs suspectes")
    suspicious_ips = stats.get("ips_suspectes", [])
    if suspicious_ips:
        df_susp = df_ips[df_ips["Adresse IP"].isin(suspicious_ips)].copy()
        if not df_susp.empty:
            st.dataframe(df_susp.reset_index(drop=True), use_container_width=True)
        else:
            st.info("Aucune correspondance dans le DataFrame.")
    else:
        st.info("Aucune IP suspecte recensée.")

with onglets[3]:
    st.subheader("Analyse Comportementale Avancée")
    st.dataframe(df_ips.reset_index(drop=True), use_container_width=True)
    st.markdown("""
    Critères de calcul du score :
    - Nombre total de paquets par IP
    - Ports sensibles (445, 3389)
    - Réputation négative
    - Nombre de raisons (alerts) détectées
    """)

with onglets[4]:
    st.subheader("Carte de géolocalisation (PyDeck)")
    data_map = []
    for ip, details in ips_data.items():
        lat = details.get("latitude")
        lon = details.get("longitude")
        if lat and lon:
            data_map.append({
                "lat": float(lat),
                "lon": float(lon),
                "ip": ip
            })
    if data_map:
        st.pydeck_chart(
            pdk.Deck(
                map_style="mapbox://styles/mapbox/light-v9",
                initial_view_state=pdk.ViewState(latitude=20, longitude=0, zoom=1),
                layers=[
                    pdk.Layer(
                        "ScatterplotLayer",
                        data=data_map,
                        get_position='[lon, lat]',
                        get_radius=30000,
                        get_color='[255, 0, 0]',
                        pickable=True
                    )
                ]
            )
        )
    else:
        st.info("Aucune donnée de latitude/longitude n’a été trouvée dans le rapport.")

st.markdown("---")
st.subheader("Télécharger le rapport JSON")
fichier_rapport = "data/rapport_analyse.json"
if os.path.exists(fichier_rapport):
    with open(fichier_rapport, "rb") as f:
        st.download_button(
            label="Télécharger le rapport",
            data=f,
            file_name="rapport_analyse.json"
        )
else:
    st.info("Le fichier rapport_analyse.json est introuvable.")

st.markdown("Fin de l’analyse – Tableau de bord avancé.")
