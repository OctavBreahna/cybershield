"""Control orar usor pentru TOTI clientii activi, indiferent de plan.

- Doar pentru tine: clientii nu primesc nimic de aici.
- Verifica: site-ul raspunde, certificatul SSL, lista Google (blacklist). Fara nmap.
- Email [WATCH] doar la schimbare, dupa 2 verificari consecutive (aprox. o ora).
- Istoricul merge in tabelele watch_state / watch_checks (nu atinge tabela scans).
"""
import os
import ssl
import socket
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from html import escape

import requests
from dotenv import load_dotenv

from database import get_connection, get_all_clients
from mailer import OWNER_EMAIL, send_checked

load_dotenv()

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

USER_AGENT = 'CyberShield-Monitor/1.0 (+https://cybersh.tech)'
CONFIRM_AFTER = 2      # verificari consecutive necesare pana trimitem email
SSL_WARN_DAYS = 14     # sub atatea zile, SSL conteaza ca problema
KEEP_DAYS = 30         # cat timp pastram istoricul orar
HEARTBEAT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'watch_heartbeat.txt')

ISSUE_ORDER = ['site_down', 'ssl_invalid', 'ssl_expiring', 'blacklist']
ISSUE_LABELS = {
    'site_down': 'Site-ul nu răspunde',
    'ssl_invalid': 'SSL invalid sau lipsă',
    'ssl_expiring': 'Certificatul SSL expiră în curând',
    'blacklist': 'Domeniul este pe lista Google (blacklist)',
}


# ---------------------------------------------------------------- verificari

def _get(url, verify):
    start = time.time()
    r = requests.get(url, timeout=10, allow_redirects=True, verify=verify,
                     headers={'User-Agent': USER_AGENT}, stream=True)
    ms = int((time.time() - start) * 1000)
    status = r.status_code
    challenge = r.headers.get('cf-mitigated', '').lower() == 'challenge'
    r.close()
    return {'status': status, 'ms': ms, 'error': None, 'challenge': challenge}


def check_site(domain):
    """Site-ul raspunde? Incearca https, apoi https fara verificare (daca doar SSL e stricat), apoi http."""
    error = None
    try:
        return _get(f'https://{domain}/', True)
    except requests.exceptions.SSLError:
        try:
            return _get(f'https://{domain}/', False)
        except requests.exceptions.RequestException as e:
            error = type(e).__name__
    except requests.exceptions.RequestException as e:
        error = type(e).__name__
    try:
        return _get(f'http://{domain}/', True)
    except requests.exceptions.RequestException as e:
        error = type(e).__name__
    return {'status': None, 'ms': None, 'error': error or 'fara raspuns', 'challenge': False}


def check_ssl(domain, port=443):
    """state: valid / invalid / unreachable (nu se poate conecta deloc pe HTTPS)."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as s:
                cert = s.getpeercert()
        expires = ssl.cert_time_to_seconds(cert['notAfter'])
        days = int((expires - time.time()) // 86400)
        if days < 0:
            return {'state': 'invalid', 'days_left': days, 'error': 'certificat expirat'}
        return {'state': 'valid', 'days_left': days, 'error': None}
    except ssl.SSLCertVerificationError as e:
        return {'state': 'invalid', 'days_left': None, 'error': e.verify_message or 'certificat invalid'}
    except ssl.SSLError:
        return {'state': 'invalid', 'days_left': None, 'error': 'eroare SSL'}
    except OSError as e:
        return {'state': 'unreachable', 'days_left': None, 'error': type(e).__name__}


def safe_browsing_listed(domain):
    """True = pe lista Google, False = curat, None = verificarea nu a mers (nu conteaza ca problema)."""
    key = os.getenv('GOOGLE_SAFE_BROWSING_KEY')
    if not key:
        return None
    body = {
        'client': {'clientId': 'cybershield', 'clientVersion': '1.0'},
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': f'http://{domain}/'}, {'url': f'https://{domain}/'}],
        },
    }
    try:
        r = requests.post('https://safebrowsing.googleapis.com/v4/threatMatches:find',
                          params={'key': key}, json=body, timeout=10)
        if r.status_code != 200:
            return None
        return bool(r.json().get('matches'))
    except Exception:
        return None


def run_check(domain):
    site = check_site(domain)
    ssl_info = check_ssl(domain)
    listed = safe_browsing_listed(domain)

    site_up = site['status'] is not None and (site['status'] < 500 or site.get('challenge', False))
    issues = []
    if not site_up:
        issues.append('site_down')
    if ssl_info['state'] == 'invalid' or (ssl_info['state'] == 'unreachable' and site_up):
        issues.append('ssl_invalid')
    elif ssl_info['state'] == 'valid' and ssl_info['days_left'] is not None and ssl_info['days_left'] < SSL_WARN_DAYS:
        issues.append('ssl_expiring')
    if listed:
        issues.append('blacklist')
    return {'site': site, 'ssl': ssl_info, 'listed': listed, 'issues': issues}


# ------------------------------------------------------------ stare / logica

def _to_set(text):
    return frozenset(x for x in (text or '').split(',') if x)


def _to_text(items):
    return ','.join(k for k in ISSUE_ORDER if k in items)


def advance(confirmed, pending, pending_count, current):
    """Returneaza (confirmed, pending, pending_count, event).
    event: None / 'new' / 'recovered' / 'changed'. Un set nou de probleme trebuie vazut
    de CONFIRM_AFTER ori la rand ca sa devina 'confirmat'."""
    current = frozenset(current)
    if current == confirmed:
        return confirmed, frozenset(), 0, None
    if current == pending:
        pending_count += 1
    else:
        pending, pending_count = current, 1
    if pending_count >= CONFIRM_AFTER:
        if not confirmed:
            event = 'new'
        elif not current:
            event = 'recovered'
        else:
            event = 'changed'
        return current, frozenset(), 0, event
    return confirmed, pending, pending_count, None


# -------------------------------------------------------------------- email

def describe(key, check):
    site, s = check['site'], check['ssl']
    if key == 'site_down':
        if site['status'] is not None:
            return f"Site-ul răspunde cu eroare HTTP {site['status']}"
        return f"Site-ul nu răspunde ({site['error'] or 'fără răspuns'})"
    if key == 'ssl_invalid':
        return f"SSL invalid sau lipsă ({s['error'] or 'conexiune HTTPS imposibilă'})"
    if key == 'ssl_expiring':
        return f"Certificatul SSL expiră în {s['days_left']} zile"
    if key == 'blacklist':
        return 'Domeniul este pe lista Google Safe Browsing'
    return key


def details_line(check):
    site, s = check['site'], check['ssl']
    if site['status'] is not None:
        http = f"HTTP {site['status']} în {site['ms']} ms"
    else:
        http = f"fără răspuns ({site['error']})"
    if s['state'] == 'valid':
        ssl_txt = f"SSL valid, {s['days_left']} zile"
    elif s['state'] == 'invalid':
        ssl_txt = 'SSL invalid'
    else:
        ssl_txt = 'HTTPS inaccesibil'
    bl = {True: 'pe listă', False: 'curat', None: 'necunoscut'}[check['listed']]
    return f'{http} · {ssl_txt} · Blacklist: {bl}'


def notify_owner(event, name, domain, plan, client_email, before, after, check):
    """Trimite emailul [WATCH] catre tine. Returneaza True daca a plecat."""
    if event == 'new':
        subject = f'[WATCH] {name} ({domain}) - problema noua'
        title, color = 'Problemă nouă confirmată', '#dc2626'
    elif event == 'recovered':
        subject = f'[WATCH] \u2705 {name} ({domain}) - revenit la normal'
        title, color = '\u2705 Revenit la normal', '#059669'
    else:
        subject = f'[WATCH] {name} ({domain}) - problemele s-au schimbat'
        title, color = 'Problemele s-au schimbat', '#d97706'

    parts = [f'<h3 style="color:{color};margin-bottom:6px;">{escape(title)}: {escape(name)}</h3>',
             f'<p><b>Domeniu:</b> {escape(domain)}<br><b>Plan:</b> {escape(plan)}<br>'
             f'<b>Email client:</b> {escape(client_email)}</p>']

    if event in ('new', 'changed'):
        items = ''.join(f'<li>{escape(describe(k, check))}</li>' for k in ISSUE_ORDER if k in after)
        parts.append(f'<p><b>Acum:</b></p><ul>{items}</ul>')
    if event in ('recovered', 'changed') and before:
        items = ''.join(f'<li>{escape(ISSUE_LABELS[k])}</li>' for k in ISSUE_ORDER if k in before)
        label = 'Probleme rezolvate' if event == 'recovered' else 'Înainte'
        parts.append(f'<p><b>{label}:</b></p><ul>{items}</ul>')

    parts.append(f'<p style="color:#475569;">Control: {escape(details_line(check))}</p>')
    parts.append('<p style="color:#475569;">Clientul nu a primit nimic de la acest control; el primește '
                 'notificări doar conform planului lui.</p>')
    html = '<div style="font-family:Arial,sans-serif">' + ''.join(parts) + '</div>'
    return send_checked(OWNER_EMAIL, subject, html)


# ------------------------------------------------------------------- baza de date

def init_tables():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS watch_state (
            client_id INTEGER PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
            confirmed TEXT NOT NULL DEFAULT '',
            pending TEXT NOT NULL DEFAULT '',
            pending_count INTEGER NOT NULL DEFAULT 0,
            updated_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS watch_checks (
            id SERIAL PRIMARY KEY,
            client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            checked_at TIMESTAMP NOT NULL DEFAULT NOW(),
            http_status INTEGER,
            response_ms INTEGER,
            ssl_state TEXT,
            ssl_days_left INTEGER,
            blacklisted BOOLEAN,
            issues TEXT NOT NULL DEFAULT ''
        )
    ''')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_watch_checks_client_time '
                'ON watch_checks (client_id, checked_at)')
    conn.commit()
    cur.close()
    conn.close()


def process_client(cur, conn, client, check):
    client_id, name, domain, email, plan = client

    cur.execute('SELECT confirmed, pending, pending_count FROM watch_state WHERE client_id = %s', (client_id,))
    row = cur.fetchone()
    if row:
        confirmed, pending, pending_count = _to_set(row[0]), _to_set(row[1]), row[2]
    else:
        confirmed, pending, pending_count = frozenset(), frozenset(), 0

    cur.execute(
        'INSERT INTO watch_checks (client_id, http_status, response_ms, ssl_state, ssl_days_left, blacklisted, issues) '
        'VALUES (%s, %s, %s, %s, %s, %s, %s)',
        (client_id, check['site']['status'], check['site']['ms'], check['ssl']['state'],
         check['ssl']['days_left'], check['listed'], _to_text(check['issues'])))

    new_confirmed, new_pending, new_count, event = advance(confirmed, pending, pending_count, check['issues'])

    if event:
        if notify_owner(event, name, domain, plan, email, confirmed, new_confirmed, check):
            print(f'[WATCH] {datetime.utcnow():%Y-%m-%d %H:%M} {name} ({domain}): {event} -> '
                  f'{_to_text(new_confirmed) or "ok"}')
        else:
            # emailul nu a plecat: pastram starea "aproape confirmata", ca sa reincerce la urmatoarea verificare
            print(f'[WATCH] {name} ({domain}): emailul nu a plecat, reincerc la urmatoarea verificare')
            new_confirmed, new_pending, new_count = confirmed, new_confirmed, CONFIRM_AFTER - 1

    cur.execute(
        'INSERT INTO watch_state (client_id, confirmed, pending, pending_count, updated_at) '
        'VALUES (%s, %s, %s, %s, NOW()) '
        'ON CONFLICT (client_id) DO UPDATE SET confirmed = EXCLUDED.confirmed, '
        'pending = EXCLUDED.pending, pending_count = EXCLUDED.pending_count, updated_at = NOW()',
        (client_id, _to_text(new_confirmed), _to_text(new_pending), new_count))
    conn.commit()


def main():
    init_tables()
    clients = get_all_clients()

    checks = {}
    if clients:
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {c[0]: pool.submit(run_check, c[2]) for c in clients}
        for cid, fut in futures.items():
            try:
                checks[cid] = fut.result()
            except Exception as e:
                print(f'[WATCH] Eroare la verificarea clientului {cid}: {e}')
                checks[cid] = None

    conn = get_connection()
    cur = conn.cursor()
    for client in clients:
        check = checks.get(client[0])
        if check is None:
            continue
        try:
            process_client(cur, conn, client, check)
        except Exception as e:
            conn.rollback()
            print(f'[WATCH] Eroare la procesarea {client[2]}: {e}')

    cur.execute('DELETE FROM watch_checks WHERE checked_at < NOW() - (%s * INTERVAL \'1 day\')', (KEEP_DAYS,))
    conn.commit()
    cur.close()
    conn.close()

    with open(HEARTBEAT_FILE, 'w') as f:
        f.write(f'{datetime.utcnow().isoformat()} UTC, {len(clients)} clienti\n')


if __name__ == '__main__':
    main()