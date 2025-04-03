import pyshark

def extract_kerberos_info(pcap_file, filter_str="kerberos.CNameString and kerberos.addr_nb"):
    """
    Parcourt le fichier PCAP et extrait, pour chaque paquet ayant à la fois
    les champs kerberos.CNameString et kerberos.addr_nb, un tuple contenant :
      - l'adresse IP source (IPv4 ou IPv6)
      - kerberos.CNameString
      - kerberos.addr_nb
      - l'adresse MAC source (via la couche Ethernet)

    Si le champ kerberos.addr_nb contient "desktop", le paquet est ignoré.
    Chaque IP source apparaîtra une seule fois dans le résultat.

    :param pcap_file: Chemin vers le fichier PCAP à analyser.
    :param filter_str: Filtre d'affichage pour limiter l'analyse aux paquets pertinents.
    :return: Liste de tuples uniques (ip, kerberos.CNameString, kerberos.addr_nb, adresseMac)
    """
    unique_results = {}

    # Ouverture de la capture avec le filtre spécifié
    capture = pyshark.FileCapture(pcap_file, display_filter=filter_str)

    for packet in capture:
        if hasattr(packet, 'kerberos'):
            kerberos_layer = packet.kerberos
            if hasattr(kerberos_layer, 'CNameString') and hasattr(kerberos_layer, 'addr_nb'):
                # Si le champ addr_nb contient "desktop" (insensible à la casse), ignorer le paquet
                if "$" in kerberos_layer.CNameString.lower():
                    continue

                # Extraction de l'adresse IP source (IPv4 ou IPv6)
                ip = None
                if hasattr(packet, 'ip'):
                    ip = packet.ip.src
                elif hasattr(packet, 'ipv6'):
                    ip = packet.ipv6.src

                # Extraction de l'adresse MAC source via la couche Ethernet
                mac = packet.eth.src if hasattr(packet, 'eth') else None

                # Ajout de l'entrée uniquement si l'IP n'est pas déjà présente
                if ip and ip not in unique_results:
                    unique_results[ip] = (ip, kerberos_layer.CNameString, kerberos_layer.addr_nb, mac)

    capture.close()
    return list(unique_results.values())
