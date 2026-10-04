from datetime import datetime

from jinja2 import Environment

TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Rapport de sécurité</title>
<style>
body { font-family: sans-serif; max-width: 700px; margin: 2rem auto; padding: 0 1rem; }
.score { font-size: 3rem; font-weight: bold; }
.ok { color: green; }
.ko { color: crimson; }
.na { color: gray; }
</style>
</head>
<body>
<h1>Rapport de sécurité</h1>
<p>Cible : {{ url }}<br>Date : {{ date }}</p>
<p class="score">{{ score }}/100</p>

<h2>En-têtes HTTP</h2>
{% if headers is none %}
<p class="ko">❌ Lecture impossible</p>
{% else %}
<ul>
{% for name, info in headers.items() %}
<li class="{{ 'ok' if info.present else 'ko' }}">{{ '✅' if info.present else '❌' }} {{ name }} : {{ info.description }}</li>
{% endfor %}
</ul>
{% endif %}

<h2>Certificat SSL</h2>
{% if ssl.valid %}
<p class="ok">✅ Valide, expire le {{ ssl.expires }} ({{ ssl.days_left }} jours)</p>
{% else %}
<p class="ko">❌ {{ ssl.error }}</p>
{% endif %}

<h2>Ports</h2>
{% if ports is none %}
<p class="na">Scan non effectué</p>
{% elif ports.error %}
<p class="ko">❌ {{ ports.error }}</p>
{% else %}
<ul>
{% for port, info in ports.items() %}
{% if info.risky %}<li class="ko">❌ Port {{ port }} ({{ info.service }}) ouvert : risque</li>
{% elif info.status == 'open' %}<li class="ok">✅ Port {{ port }} ({{ info.service }}) ouvert</li>
{% elif info.status == 'closed' %}<li class="na">➖ Port {{ port }} ({{ info.service }}) fermé</li>
{% else %}<li class="na">❓ Port {{ port }} ({{ info.service }}) sans réponse</li>
{% endif %}
{% endfor %}
</ul>
{% endif %}
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


def generate_report(url, headers, ssl_result, ports, score, path):
    env = Environment(autoescape=True)
    template = env.from_string(TEMPLATE)
    html = template.render(
        url=url,
        date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        score=score,
        headers=headers,
        ssl=ssl_result,
        ports=ports,
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
