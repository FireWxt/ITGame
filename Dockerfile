# Dockerfile
FROM python:3.10-slim

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    build-essential curl && \
    apt-get clean

# Création du répertoire de travail
WORKDIR /app

# Copie des fichiers
COPY . /app

# Installation des dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Exposition du port utilisé par Streamlit
EXPOSE 8501

# Lancement du dashboard
CMD ["streamlit", "run", "dashboard.py", "--server.port=8501", "--server.address=0.0.0.0"]
