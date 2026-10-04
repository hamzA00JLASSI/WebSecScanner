import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": "Protège contre le XSS",
    "Strict-Transport-Security": "Force l'utilisation de HTTPS",
    "X-Frame-Options": "Protège contre le clickjacking",
    "X-Content-Type-Options": "Empêche le MIME sniffing",
}


def check_headers(url):
    response = requests.get(url, timeout=10)
    results = {}
    for header, description in SECURITY_HEADERS.items():
        results[header] = {
            "present": header in response.headers,
            "description": description,
        }
    return results
