from datetime import datetime

from jinja2 import Environment

HEADER_FIXES = {
    "Content-Security-Policy": "Ajoutez un en-tête Content-Security-Policy qui limite les sources de scripts autorisées (ex. default-src 'self').",
    "Strict-Transport-Security": "Ajoutez Strict-Transport-Security: max-age=31536000; includeSubDomains pour forcer HTTPS.",
    "X-Frame-Options": "Ajoutez X-Frame-Options: DENY (ou SAMEORIGIN) pour bloquer le clickjacking.",
    "X-Content-Type-Options": "Ajoutez X-Content-Type-Options: nosniff pour empêcher le MIME sniffing.",
}

TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport de sécurité - {{ url }}</title>
<style>
:root {
  --bg: #f3f4f6; --card: #ffffff; --text: #111827; --muted: #6b7280;
  --border: #e5e7eb; --ok: #15803d; --ok-bg: #dcfce7;
  --ko: #b91c1c; --ko-bg: #fee2e2; --na: #4b5563; --na-bg: #f3f4f6;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text); line-height: 1.5;
  font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.wrap { max-width: 860px; margin: 0 auto; padding: 2rem 1rem 3rem; }
.good { --c: #16a34a; }
.mid { --c: #d97706; }
.bad { --c: #dc2626; }

.top {
  background: linear-gradient(135deg, #0f172a, #1e3a8a); color: #fff;
  border-radius: 12px; padding: 1.75rem 2rem; margin-bottom: 1.5rem;
  display: flex; justify-content: space-between; align-items: center;
  gap: 1.5rem; flex-wrap: wrap;
}
.top h1 { margin: 0 0 .25rem; font-size: 1.6rem; }
.top p { margin: .15rem 0; color: #cbd5e1; font-size: .95rem; word-break: break-all; }
.verdict {
  display: inline-block; margin-top: .75rem; padding: .25rem .75rem;
  border-radius: 999px; background: var(--c); color: #fff;
  font-weight: 600; font-size: .85rem;
}
.gauge {
  width: 130px; height: 130px; border-radius: 50%; display: grid; place-items: center;
  background: conic-gradient(var(--c) calc(var(--p) * 1%), rgba(255,255,255,.2) 0);
}
.gauge-inner {
  width: 104px; height: 104px; border-radius: 50%; background: #0f172a;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
}
.gauge-inner strong { font-size: 2rem; line-height: 1; }
.gauge-inner span { font-size: .75rem; color: #cbd5e1; }

.card {
  background: var(--card); border: 1px solid var(--border); border-radius: 12px;
  padding: 1.25rem 1.5rem; margin-bottom: 1.25rem;
  box-shadow: 0 1px 3px rgba(0,0,0,.06);
}
.card h2 { margin: 0 0 .75rem; font-size: 1.15rem; }
table { width: 100%; border-collapse: collapse; font-size: .95rem; }
th, td { text-align: left; padding: .6rem .5rem; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }
tr:last-child td { border-bottom: none; }
code { background: var(--na-bg); padding: .1rem .4rem; border-radius: 4px; font-size: .88rem; }
.badge {
  display: inline-block; padding: .15rem .6rem; border-radius: 999px;
  font-size: .78rem; font-weight: 600; white-space: nowrap;
}
.badge.ok { background: var(--ok-bg); color: var(--ok); }
.badge.ko { background: var(--ko-bg); color: var(--ko); }
.badge.na { background: var(--na-bg); color: var(--na); }
.muted { color: var(--muted); }
ul.recs { margin: 0; padding-left: 1.2rem; }
ul.recs li { margin: .4rem 0; }
footer { text-align: center; color: var(--muted); font-size: .8rem; margin-top: 2rem; }

@media print {
  body { background: #fff; }
  .card { box-shadow: none; break-inside: avoid; }
  .top, .gauge, .verdict, .badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
</style>
</head>
<body>
<div class="wrap">

<div class="top {{ level }}">
  <div>
    <h1>Rapport de sécurité</h1>
    <p>Cible : {{ url }}</p>
    <p>Date : {{ date }}</p>
    <span class="verdict">{{ label }}</span>
  </div>
  <div class="gauge" style="--p: {{ score }}">
    <div class="gauge-inner"><strong>{{ score }}</strong><span>sur 100</span></div>
  </div>
</div>

<div class="card">
  <h2>En-têtes HTTP</h2>
  {% if headers is none %}
  <span class="badge ko">Lecture impossible</span>
  {% else %}
  <table>
    <thead><tr><th>Statut</th><th>En-tête</th><th>Rôle</th></tr></thead>
    <tbody>
    {% for name, info in headers.items() %}
    <tr>
      <td><span class="badge {{ 'ok' if info.present else 'ko' }}">{{ 'Présent' if info.present else 'Manquant' }}</span></td>
      <td><code>{{ name }}</code></td>
      <td>{{ info.description }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}
</div>

<div class="card">
  <h2>Certificat SSL/TLS</h2>
  {% if ssl.valid %}
  <p>
    <span class="badge ok">Valide</span>
    {% if ssl.days_left < 30 %}<span class="badge ko">Expire bientôt</span>{% endif %}
  </p>
  <p class="muted">Expire le {{ ssl.expires }} ({{ ssl.days_left }} jours restants)</p>
  {% else %}
  <p><span class="badge ko">Problème</span></p>
  <p class="muted">{{ ssl.error }}</p>
  {% endif %}
</div>

<div class="card">
  <h2>Ports</h2>
  {% if ports is none %}
  <span class="badge na">Scan non effectué</span>
  {% elif ports.error %}
  <span class="badge ko">{{ ports.error }}</span>
  {% else %}
  <table>
    <thead><tr><th>Port</th><th>Service</th><th>État</th></tr></thead>
    <tbody>
    {% for port, info in ports.items() %}
    <tr>
      <td><code>{{ port }}</code></td>
      <td>{{ info.service }}</td>
      <td>
      {% if info.risky %}<span class="badge ko">Ouvert - risque</span>
      {% elif info.status == 'open' %}<span class="badge ok">Ouvert</span>
      {% elif info.status == 'closed' %}<span class="badge na">Fermé</span>
      {% else %}<span class="badge na">Sans réponse</span>
      {% endif %}
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}
</div>

<div class="card">
  <h2>Recommandations</h2>
  {% if recs %}
  <ul class="recs">
    {% for rec in recs %}<li>{{ rec }}</li>{% endfor %}
  </ul>
  {% else %}
  <p><span class="badge ok">Rien à signaler</span> Aucune action nécessaire sur les points testés.</p>
  {% endif %}
</div>

<footer>Généré par WebSecScanner. À utiliser uniquement sur des systèmes dont vous avez l'autorisation.</footer>
</div>
</body>
</html>
"""


def compute_score(headers, ssl_result, ports):
    earned = 0
    total = 60 + 20

    if headers is not None:
        earned += 15 * sum(1 for info in headers.values() if info["present"])

    if ssl_result["valid"]:
        earned += 20 if ssl_result["days_left"] >= 30 else 10

    if ports is not None and "error" not in ports:
        total += 20
        risky = sum(1 for info in ports.values() if info["risky"])
        earned += max(0, 20 - 10 * risky)

    return round(earned / total * 100)


def score_level(score):
    if score >= 80:
        return "good", "Bon niveau"
    if score >= 50:
        return "mid", "À améliorer"
    return "bad", "Critique"


def build_recommendations(headers, ssl_result, ports):
    recs = []

    if headers is not None:
        for name, info in headers.items():
            if not info["present"]:
                recs.append(HEADER_FIXES[name])

    if not ssl_result["valid"]:
        recs.append("Corrigez ou renouvelez le certificat SSL/TLS.")
    elif ssl_result["days_left"] < 30:
        recs.append("Renouvelez le certificat SSL/TLS : il expire dans moins de 30 jours.")

    if ports is not None and "error" not in ports:
        for port, info in ports.items():
            if info["risky"]:
                recs.append(
                    f"Fermez ou filtrez le port {port} ({info['service']}) avec un pare-feu."
                )

    return recs


def generate_report(url, headers, ssl_result, ports, score, path):
    level, label = score_level(score)
    env = Environment(autoescape=True)
    template = env.from_string(TEMPLATE)
    html = template.render(
        url=url,
        date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        score=score,
        level=level,
        label=label,
        headers=headers,
        ssl=ssl_result,
        ports=ports,
        recs=build_recommendations(headers, ssl_result, ports),
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
