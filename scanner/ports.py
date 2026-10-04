import errno
import socket
from urllib.parse import urlparse

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP alternatif",
}

RISKY_PORTS = {21, 3306}


def scan_ports(url, ports=COMMON_PORTS):
    hostname = urlparse(url).hostname

    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return {"error": f"Nom de domaine introuvable : {hostname}"}

    results = {}
    for port, service in ports.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            code = sock.connect_ex((ip, port))

        if code == 0:
            status = "open"
        elif code == errno.ECONNREFUSED:
            status = "closed"
        else:
            status = "no_response"

        results[port] = {
            "service": service,
            "status": status,
            "code": code,
            "risky": status == "open" and port in RISKY_PORTS,
        }
    return results
