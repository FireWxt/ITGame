from collections import defaultdict

# Liste des ports connus pour être utilisés dans des attaques 
SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    5900: "VNC"
}

def analyse_ports(capture):
    """
    Analyse les ports des paquets dans une capture PCAP.
    """
    port_counts = defaultdict(int)
    suspicious_found = set()

    for packet in capture:
        try:
            if hasattr(packet, 'tcp'):
                dport = int(packet.tcp.dstport)
                port_counts[dport] += 1
                if dport in SUSPICIOUS_PORTS:
                    suspicious_found.add(dport)
            elif hasattr(packet, 'udp'):
                dport = int(packet.udp.dstport)
                port_counts[dport] += 1
                if dport in SUSPICIOUS_PORTS:
                    suspicious_found.add(dport)
        except Exception:
            continue

    return dict(port_counts), list(suspicious_found)
