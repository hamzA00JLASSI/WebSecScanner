import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


def check_ssl(url):
    hostname = urlparse(url).hostname
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": f"Certificat invalide : {e.verify_message}"}
    except OSError as e:
        return {"valid": False, "error": f"Connexion impossible : {e}"}

    expires_ts = ssl.cert_time_to_seconds(cert["notAfter"])
    expires = datetime.fromtimestamp(expires_ts, tz=timezone.utc)
    days_left = (expires - datetime.now(timezone.utc)).days

    return {
        "valid": True,
        "expires": expires.strftime("%Y-%m-%d"),
        "days_left": days_left,
    }
