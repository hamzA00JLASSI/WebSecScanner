# WebSecScanner

Scanner de sécurité web en Python. Il analyse un site et génère un score sur 100 avec un rapport HTML et des recommandations.

## Fonctionnalités

- Vérification des en-têtes HTTP de sécurité (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Contrôle du certificat SSL/TLS (validité, jours avant expiration)
- Scan des ports courants (option `--ports`)
- Score de sécurité sur 100
- Rapport HTML avec recommandations de correction

## Prérequis

- Python 3.8 ou plus
- Git

## Installation

```bash
git clone https://github.com/hamzA00JLASSI/WebSecScanner.git
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

### Exemple de sortie

```
Analyse de https://example.com

--- En-têtes HTTP ---
❌ Content-Security-Policy: Protège contre le XSS
❌ Strict-Transport-Security: Force l'utilisation de HTTPS
❌ X-Frame-Options: Protège contre le clickjacking
❌ X-Content-Type-Options: Empêche le MIME sniffing

--- Certificat SSL ---
✅ Certificat valide, expire le 2026-12-25 (82 jours)

Score : 25/100
```

## Générer un PDF

L'outil produit un rapport HTML. Pour l'obtenir en PDF, ouvrez-le dans un navigateur, puis `Ctrl+P` → « Enregistrer au format PDF » (cochez « Imprimer les arrière-plans » pour garder les couleurs).

## Barème du score

| Test | Points |
|---|---|
| En-têtes HTTP | 60 (15 par en-tête) |
| Certificat SSL | 20 (10 s'il expire dans moins de 30 jours) |
| Ports | 20 (-10 par port risqué ouvert), seulement avec `--ports` |

## Structure

```
main.py                point d'entrée (arguments, affichage)
scanner/headers.py     en-têtes HTTP
scanner/ssl_check.py   certificat SSL
scanner/ports.py       scan de ports
scanner/report.py      score et rapport HTML
```

## Avertissement légal

Cet outil est destiné à un usage éducatif et défensif.

- **Analyse passive** (en-têtes HTTP, certificat SSL) : elle envoie une requête comme un navigateur, mais respectez les conditions d'utilisation du site et ne lancez pas l'outil en boucle.
- **Scan de ports** (`--ports`) : uniquement sur des systèmes dont vous êtes propriétaire ou pour lesquels vous avez une **autorisation écrite**. Sans autorisation, c'est potentiellement illégal.

Cibles de test recommandées : `localhost`, `example.com`, `expired.badssl.com`, et `scanme.nmap.org` (avec modération, scan de ports autorisé par ses propriétaires).

L'auteur décline toute responsabilité en cas d'usage non autorisé.

## Pistes d'amélioration

- Option `--pdf` pour exporter directement le rapport en PDF
- Scan de ports en parallèle
- Détection de la version du serveur
- Tests automatiques avec pytest
