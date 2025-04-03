import streamlit as st
import pandas as pd
import pydeck as pdk
import json
import subprocess
import os
from fpdf import FPDF
import matplotlib.pyplot as plt

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

# Fonction pour colorer uniquement le texte en fonction de la valeur
def color_risk(val):
    if val == "Faible":
        return "color: green;"
    elif val == "Moyen":
        return "color: orange;"
    elif val == "Élevé":
        return "color: red;"
    elif val == "Critique":
        return "color: #8B0000;"
    return ""

def generate_pdf(rapport, df_ports, df_mitre, df_ips):
    """
    Génère un rapport PDF contenant les statistiques générales, les IPs suspectes,
    les tactiques MITRE ATT&CK et les graphiques.
    """
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Rapport d'Analyse Réseau", ln=True, align="C")
    pdf.ln(10)

    # Statistiques générales
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt="Statistiques Générales :", ln=True)
    stats = rapport.get("statistiques", {})
    pdf.cell(200, 10, txt=f"Total de paquets : {stats.get('total_paquets', 0)}", ln=True)
    pdf.cell(200, 10, txt=f"IPs analysées : {stats.get('ips_analysees', 0)}", ln=True)
    pdf.cell(200, 10, txt=f"Échecs Kerberos : {stats.get('echouements_kerberos', 0)}", ln=True)
    pdf.cell(200, 10, txt=f"Téléchargements binaires HTTP : {stats.get('telechargements_binaires_http', 0)}", ln=True)
    pdf.ln(10)

    # Graphique des ports
    if not df_ports.empty:
        # Limiter à 10 ports les plus utilisés
        df_ports = df_ports.nlargest(10, "count")  # Trier et sélectionner les 10 premiers
        plt.figure(figsize=(10, 4))
        df_ports.set_index("port")["count"].plot(kind="bar", color="skyblue", rot=45)
        plt.title("Top 10 des Ports")
        plt.xlabel("Port")
        plt.ylabel("Nombre de connexions")
        plt.tight_layout()
        plt.savefig("ports_chart.png")
        plt.close()
        pdf.cell(200, 10, txt="Graphique : Top 10 des Ports", ln=True, align="C")
        pdf.image("ports_chart.png", x=10, y=pdf.get_y() + 5, w=180)
        pdf.ln(70)

    # Tactiques MITRE ATT&CK
    pdf.ln(5)
    if not df_mitre.empty:
        plt.figure(figsize=(10, 4))
        df_mitre.set_index("Tactique")["Occurrences"].plot(kind="bar", color="orange")
        plt.title("Tactiques MITRE ATT&CK")
        plt.xlabel("Tactique")
        plt.ylabel("Occurrences")
        plt.tight_layout()
        plt.savefig("mitre_chart.png")
        plt.close()
        pdf.image("mitre_chart.png", x=10, y=pdf.get_y() + 5, w=180)
        pdf.ln(70)
    else:
        pdf.cell(200, 10, txt="Aucune tactique MITRE détectée.", ln=True)
    pdf.ln(35)

    # IPs suspectes
    # IPs suspectes
    pdf.cell(200, 10, txt="Détails des IPs suspectes :", ln=True)
    pdf.ln(5)

    # Récupérer les IPs suspectes depuis le rapport JSON
    suspicious_ips = rapport.get("statistiques", {}).get("ips_suspectes", [])
    ips_details = rapport.get("ips", {})

    if suspicious_ips:
        for ip in suspicious_ips:
            details = ips_details.get(ip, {})
            pdf.cell(200, 10, txt=f"IP : {ip}", ln=True)
            pdf.cell(200, 10, txt=f"  - Nombre de paquets : {details.get('count', 0)}", ln=True)
            pdf.cell(200, 10, txt=f"  - Nombre de ports : {len(details.get('ports', []))}", ln=True)
            pdf.cell(200, 10, txt=f"  - Risque : {details.get('risk', 'Inconnu')}", ln=True)
            pdf.cell(200, 10, txt=f"  - Pays : {details.get('country', 'Inconnu')}", ln=True)
            pdf.cell(200, 10, txt=f"  - Raisons : {', '.join(details.get('reasons', ['Aucune raison']))[:200]}", ln=True)
            pdf.ln(5)
    else:
        pdf.cell(200, 10, txt="Aucune IP suspecte détectée.", ln=True)
    pdf.ln(10)

    # Sauvegarder le PDF
    pdf_path = "rapport_analyse.pdf"
    pdf.output(pdf_path)
    return pdf_path

# Fonction pour ajouter un point coloré à côté de l'IP en fonction du risque
def format_ip_with_risk(ip, risk):
    if risk == "Faible":
        return f'<span style="color: green;">●</span> {ip}'
    elif risk == "Moyen":
        return f'<span style="color: orange;">●</span> {ip}'
    elif risk == "Élevé":
        return f'<span style="color: red;">●</span> {ip}'
    elif risk == "Critique":
        return f'<span style="color: #8B0000;">●</span> {ip}'
    return ip

# Fonction pour colorer uniquement le texte en fonction de la valeur
def format_risk_with_color(val):
    if val == "Faible":
        return '<span style="color: green;">Faible</span>'
    elif val == "Moyen":
        return '<span style="color: orange;">Moyen</span>'
    elif val == "Élevé":
        return '<span style="color: red;">Élevé</span>'
    elif val == "Critique":
        return '<span style="color: #8B0000;">Critique</span>'
    return val

# Afficher le logo en haut à gauche
col1, col2 = st.columns([1, 9])
with col1:
    st.image("assets/logo.png", width=150)
with col2:
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
        "Raisons": "; ".join(details["reasons"][:3])  # Affichage limité
    })


df_ips = pd.DataFrame(liste_ip).sort_values(by="Score", ascending=False)

# Création de plusieurs onglets
onglets = st.tabs(["Statistiques Générales", "Tactiques MITRE", "IPs Suspectes", "Analyse Comportementale", "Carte"])
# Application du style
styled_df = df_ips.style.applymap(color_risk, subset=["Risque"])

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
            df_susp["Adresse IP"] = df_susp.apply(lambda row: format_ip_with_risk(row["Adresse IP"], row["Risque"]), axis=1)
            df_susp["Risque"] = df_susp["Risque"].apply(format_risk_with_color)
            st.write(df_susp.to_html(escape=False, index=False), unsafe_allow_html=True)
        else:
            st.info("Aucune correspondance dans le DataFrame.")
    else:
        st.info("Aucune IP suspecte recensée.")

with onglets[3]:
    st.subheader("Analyse Comportementale Avancée")
    if not df_ips.empty:
        df_ips["Adresse IP"] = df_ips.apply(lambda row: format_ip_with_risk(row["Adresse IP"], row["Risque"]), axis=1)
        df_ips["Risque"] = df_ips["Risque"].apply(format_risk_with_color)
        st.write(df_ips.to_html(escape=False, index=False), unsafe_allow_html=True)
    else:
        st.info("Aucune donnée disponible pour l'analyse comportementale.")

with onglets[4]:
    st.subheader("Carte de géolocalisation")
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
st.subheader("Télécharger le rapport")
pdf_path = generate_pdf(rapport, pd.DataFrame(ports_analyse), pd.DataFrame(list(mitre_data.items()), columns=["Tactique", "Occurrences"]), df_ips)
with open(pdf_path, "rb") as f:
    st.download_button(
        label="Télécharger le rapport PDF",
        data=f,
        file_name="rapport_analyse.pdf",
        mime="application/pdf"
    )

st.markdown("Fin de l’analyse – Tableau de bord avancé.")
