import argparse

import requests

from scanner.headers import check_headers
from scanner.ports import scan_ports
from scanner.ssl_check import check_ssl


def main():
    parser = argparse.ArgumentParser(description="Scanner de sécurité web")
    parser.add_argument("url", help="URL à analyser (ex: https://example.com)")
    parser.add_argument(
        "--ports",
        action="store_true",
        help="Active le scan de ports (uniquement sur des cibles autorisées)",
    )
    args = parser.parse_args()

    print(f"Analyse de {args.url}\n")

    print("--- En-têtes HTTP ---")
    try:
        results = check_headers(args.url)
        for header, info in results.items():
            status = "✅" if info["present"] else "❌"
            print(f"{status} {header}: {info['description']}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Impossible de lire les en-têtes ({type(e).__name__})")

    print("\n--- Certificat SSL ---")
    ssl_result = check_ssl(args.url)
    if ssl_result["valid"]:
        print(f"✅ Certificat valide, expire le {ssl_result['expires']} ({ssl_result['days_left']} jours)")
    else:
        print(f"❌ {ssl_result['error']}")

    if args.ports:
        print("\n--- Ports ---")
        port_results = scan_ports(args.url)
        if "error" in port_results:
            print(f"❌ {port_results['error']}")
        else:
            for port, info in port_results.items():
                if info["risky"]:
                    print(f"❌ Port {port} ({info['service']}) ouvert : risque")
                elif info["status"] == "open":
                    print(f"✅ Port {port} ({info['service']}) ouvert")
                elif info["status"] == "closed":
                    print(f"➖ Port {port} ({info['service']}) fermé")
                else:
                    print(f"❓ Port {port} ({info['service']}) sans réponse (code {info['code']})")


if __name__ == "__main__":
    main()
