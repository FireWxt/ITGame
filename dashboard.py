import streamlit as st
import pandas as pd
import pydeck as pdk
import json
import subprocess
import os
from fpdf import FPDF
import matplotlib.pyplot as plt

st.set_page_config(page_title="DATALYTICS", layout="wide")

st.markdown("""
    <style>
    .styled-table {
        border-collapse: collapse;
        margin: 10px 0;
        font-size: 14px;
        width: 100%;
        border: 1px solid #ddd;
    }
    .styled-table th,
    .styled-table td {
        padding: 10px 12px;
        text-align: left;
    }
    .styled-table th {
        background-color: #1f77b4;
        color: white;
    }
    .styled-table tr:nth-child(even) {
        background-color: #f2f2f2;
    }
    </style>
""", unsafe_allow_html=True)

col1, col2 = st.columns([1, 9])
with col1:
    st.image("assets/logo.png", width=350)
with col2:
    st.markdown("<h1 style='color:#1996a6;'>DATALYTICS - Analyse Réseau</h1>", unsafe_allow_html=True)

def lancer_analyse():
    with st.spinner("Analyse en cours..."):
        result = subprocess.run(["python", "analyse.py"], capture_output=True, text=True)
        if result.returncode == 0:
            st.success("Analyse terminée avec succès.")
        else:
            st.error("Erreur lors de l’analyse.")
            st.code(result.stderr)

def charger_rapport():
    chemin_rapport = "data/rapport_analyse.json"
    if not os.path.exists(chemin_rapport):
        return None
    try:
        with open(chemin_rapport, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return None

def calcul_score(details):
    base_score = 0
    count = details["count"]
    nb_reasons = len(details["reasons"])
    if count > 2000:
        base_score += 30
    elif count > 500:
        base_score += 15
    elif count > 100:
        base_score += 5
    sensitive_ports = {445, 3389}
    if len(sensitive_ports.intersection(details["ports"])) > 0:
        base_score += 20
    if any("Réputation négative" in reason for reason in details["reasons"]):
        base_score += 30
    if nb_reasons > 20:
        base_score += 10
    elif nb_reasons > 5:
        base_score += 5
    return min(base_score, 100)

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
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Rapport d'Analyse ", ln=True, align="C")
    pdf.ln(10)
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt="Statistiques Générales :", ln=True)
    stats = rapport.get("statistiques", {})
    pdf.cell(200, 10, txt=f"Total de paquets : {stats.get('total_paquets', 0)}", ln=True)
    pdf.cell(200, 10, txt=f"IPs analysées : {stats.get('ips_analysees', 0)}", ln=True)
    pdf.cell(200, 10, txt=f"Échecs Kerberos : {stats.get('echouements_kerberos', 0)}", ln=True)
    pdf.cell(200, 10, txt=f"Téléchargements binaires HTTP : {stats.get('telechargements_binaires_http', 0)}", ln=True)
    pdf.ln(10)
    if not df_ports.empty:
        df_ports = df_ports.nlargest(10, "count")
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
    pdf.ln(45)
    pdf.cell(200, 10, txt="Détails des IPs suspectes :", ln=True)
    pdf.ln(5)
    suspicious_ips = stats.get("ips_suspectes", [])
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
    pdf_path = "rapport_analyse.pdf"
    pdf.output(pdf_path)
    return pdf_path

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

if st.button("Lancer une nouvelle analyse PCAP"):
    lancer_analyse()

rapport = charger_rapport()
if not rapport:
    st.warning("Aucun rapport trouvé. Lancez l'analyse ou vérifiez 'data/rapport_analyse.json'.")
    st.stop()

with st.expander("Voir tout le rapport JSON"):
    st.subheader("Contenu complet du fichier rapport_analyse.json")
    st.json(rapport)

stats = rapport.get("statistiques", {})
ips_data = rapport.get("ips", {})
mitre_data = rapport.get("mitre_attacks", {})
ports_analyse = rapport.get("ports_analyse", [])
kerberos_flags = rapport.get("Flags ", [])
api_responses = rapport.get("api_responses", [])

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
        "Raisons": "; ".join(details["reasons"][:3])
    })
df_ips = pd.DataFrame(liste_ip).sort_values(by="Score", ascending=False)
styled_df = df_ips.style.map(color_risk, subset=["Risque"])

onglets = st.tabs(["Statistiques Générales", "IPs Suspectes", "Analyse Comportementale", "Carte", "Flags Kerberos", "Réponses de l'API"])

with onglets[0]:
    suspicious_ips = stats.get("ips_suspectes", [])
    st.subheader("Statistiques Générales")
    col1, col2, col3, col4 = st.columns(4)
    col2.metric("Total Paquets", stats.get("total_paquets", 0))
    col3.metric("IPs Suspectes", len(suspicious_ips))
    col4.metric("IPs Analysées", stats.get("ips_analysees", 0))
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
    st.subheader("Détails des IPs suspectes")
    if suspicious_ips:
        df_susp = df_ips[df_ips["Adresse IP"].isin(suspicious_ips)].copy()
        if not df_susp.empty:
            df_susp["Adresse IP"] = df_susp.apply(lambda row: format_ip_with_risk(row["Adresse IP"], row["Risque"]), axis=1)
            df_susp["Risque"] = df_susp["Risque"].apply(format_risk_with_color)
            st.write(df_susp.to_html(classes="styled-table", escape=False, index=False), unsafe_allow_html=True)
        else:
            st.info("Aucune correspondance dans la DataFrame.")
    else:
        st.info("Aucune IP suspecte recensée.")

with onglets[2]:
    st.subheader("Analyse Comportementale Avancée")
    if not df_ips.empty:
        df_ips["Adresse IP"] = df_ips.apply(lambda row: format_ip_with_risk(row["Adresse IP"], row["Risque"]), axis=1)
        df_ips["Risque"] = df_ips["Risque"].apply(format_risk_with_color)
        st.write(df_ips.to_html(escape=False, index=False), unsafe_allow_html=True)
    else:
        st.info("Aucune donnée disponible pour l'analyse comportementale.")

with onglets[3]:
    st.subheader("Carte de géolocalisation")
    data_map = []
    for ip, details in ips_data.items():
        lat = details.get("latitude")
        lon = details.get("longitude")
        if lat and lon:
            data_map.append({"lat": float(lat), "lon": float(lon), "ip": ip})
    if data_map:
        st.pydeck_chart(pdk.Deck(
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
        ))
    else:
        st.info("Aucune donnée de latitude/longitude n’a été trouvée dans le rapport.")

with onglets[4]:
    st.subheader("Flags Kerberos associés aux machines infectées")
    infected_machines = stats.get("machines_possiblement_infectees", [])
    if infected_machines:
        for machine in infected_machines:
            st.markdown(f"**Machine infectée :** `{machine}`")
            matching_flags = [flag for flag in kerberos_flags if isinstance(flag, list) and len(flag) >= 4 and flag[0] == machine]
            if matching_flags:
                for idx, flag in enumerate(matching_flags, start=1):
                    ip, user, hostname, mac = flag[:4]
                    st.markdown(f"**Flag #{idx}**")
                    st.markdown(f"- **IP :** {ip}")
                    st.markdown(f"- **Utilisateur :** {user}")
                    st.markdown(f"- **Machine :** {hostname}")
                    st.markdown(f"- **MAC :** {mac}")
            else:
                st.info("Aucun flag Kerberos associé à cette machine.")
            st.markdown("---")
    else:
        st.info("Aucune machine infectée détectée.")

with onglets[5]:
    st.subheader("Réponses de l'API")
    if api_responses:
        for i, resp in enumerate(api_responses, start=1):
            st.markdown(f"**Réponse #{i}** :")
            st.json(resp)
    else:
        st.info("Aucune réponse de l'API n'a été trouvée dans le rapport.")

st.markdown("---")
st.subheader("Télécharger le rapport")
df_mitre = pd.DataFrame(list(mitre_data.items()), columns=["Tactique", "Occurrences"]) if mitre_data else pd.DataFrame()
pdf_path = generate_pdf(rapport, pd.DataFrame(ports_analyse), df_mitre, df_ips)
with open(pdf_path, "rb") as f:
    st.download_button(label="Télécharger le rapport PDF", data=f, file_name="rapport_analyse.pdf", mime="application/pdf")

st.markdown("Fin de l’analyse – Tableau de bord")
