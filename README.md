# WebSecScanner

Scanner de sécurité web en Python. Il analyse un site et génère un score sur 100 avec un rapport HTML et des recommandations.

## Fonctionnalités

- Vérification des en-têtes HTTP de sécurité (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Contrôle du certificat SSL/TLS (validité, jours avant expiration)
- Scan des ports courants (option `--ports`)
- Score de sécurité sur 100
- Rapport HTML avec recommandations de correction

## Installation

```bash
git clone git@github.com:hamzA00JLASSI/WebSecScanner.git
cd WebSecScanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Sous Windows, l'activation du venv se fait avec `venv\Scripts\activate`.

## Utilisation

```bash
python main.py https://example.com
python main.py https://example.com --output rapport.html
python main.py http://localhost:8080 --ports
```

| Option | Rôle |
|---|---|
| `--ports` | Active le scan de ports (cibles autorisées uniquement) |
| `--output FICHIER` | Génère un rapport HTML |

## Barème du score

| Test | Points |
|---|---|
| En-têtes HTTP | 60 (15 par en-tête) |
| Certificat SSL | 20 (10 s'il expire dans moins de 30 jours) |
| Ports | 20 (-10 par port risqué ouvert), seulement avec `--ports` |

## Structure

```
main.py            point d'entrée (arguments, affichage)
scanner/headers.py en-têtes HTTP
scanner/ssl_check.py certificat SSL
scanner/ports.py   scan de ports
scanner/report.py  score et rapport HTML
```

## Avertissement légal

Utilisez cet outil uniquement sur des systèmes dont vous êtes propriétaire ou pour lesquels vous avez une autorisation écrite. Le scan de ports ou les tests de sécurité sans autorisation peuvent être illégaux.

Cibles de test légales : `localhost`, `expired.badssl.com`, `scanme.nmap.org` (avec modération).

## Pistes d'amélioration

- Scan de ports en parallèle
- Export PDF du rapport
- Détection de la version du serveur
