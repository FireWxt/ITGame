def get_mitre_signatures():
    return {
        "Initial Access": [
            lambda pkt: "http" in pkt.lower() and (".exe" in pkt or ".bin" in pkt),
        ],
        "Execution": [
            lambda pkt: "powershell" in pkt.lower(),
        ],
        "Persistence": [
            lambda pkt: "autorun" in pkt.lower() or "schtasks" in pkt.lower(),
        ],
        "Privilege Escalation": [
            lambda pkt: "token" in pkt.lower() and "privilege" in pkt.lower(),
        ],
        "Defense Evasion": [
            lambda pkt: "flags_reset" in pkt.lower(),
        ],
        "Credential Access": [
            lambda pkt: "kerberos" in pkt.lower() and "krb5kdc_err_preauth_required" in pkt.lower(),
        ],
        "Discovery": [
            lambda pkt: "nmap" in pkt.lower() or "scan" in pkt.lower(),
        ],
        "Lateral Movement": [
            lambda pkt: "smb" in pkt.lower() or "rdp" in pkt.lower(),
        ],
        "Collection": [
            lambda pkt: "ftp" in pkt.lower() or (hasattr(pkt, 'length') and int(pkt.length) > 1500),
        ],
    }
