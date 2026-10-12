import os
import sys
from mailer import send_checked
from html import escape
from dotenv import load_dotenv
from scanner import scan
from alerts import send_alert
from database import get_all_clients, save_scan, get_last_scan
from datetime import datetime

load_dotenv()

# Aici primesti tu notificarile interne
OWNER_EMAIL = 'cybersh.official@gmail.com'

# python3 run_all_scans.py --premium  ->  scaneaza doar clientii Premium
PREMIUM_RUN = '--premium' in sys.argv

DANGEROUS_PORTS = (21, 23, 3306, 5432)
ALERT_THRESHOLD = 90  # sub acest scor apare o problema

def should_scan_today(plan):
    if PREMIUM_RUN:
        return plan == 'premium'

    day = datetime.utcnow().weekday()  # 0=Luni, 6=Duminica

    if plan == 'basic':
        return day == 0  # Doar luni
    elif plan == 'standard':
        return True  # In fiecare zi
    return False  # premium se scaneaza prin rularea frecventa (--premium)

def send_html(to_email, subject, html):
    return send_checked(to_email, subject, html)

def find_problems(result):
    """Lista de (cheie, text_ro, text_en_rezolvat) pentru problemele dintr-o scanare."""
    problems = []
    for p in result['ports']:
        if p['port'] in DANGEROUS_PORTS and p['state'] == 'open':
            problems.append((
                f"port:{p['port']}",
                f"Port periculos deschis: {p['port']}",
                f"Dangerous port {p['port']} was open"
            ))
    ssl = result['ssl']
    if not ssl.get('valid'):
        problems.append((
            'ssl_invalid',
            'SSL invalid sau expirat',
            'SSL certificate was invalid or expired'
        ))
    elif ssl.get('days_left', 999) < 30:
        problems.append((
            'ssl_expiring',
            f"SSL expira in {ssl['days_left']} zile",
            'SSL certificate was close to expiring'
        ))
    if result['blacklist'].get('blacklisted'):
        problems.append((
            'blacklist',
            'Domeniul este pe blacklist',
            'Domain was on a blacklist'
        ))
    return problems

def list_problems(result):
    problems = [ro for _, ro, _ in find_problems(result)]
    if not problems:
        problems.append('Scor sub 90 (vezi raportul)')
    return problems

def notify_owner(name, domain, plan, client_email, result, client_note):
    """Email intern pentru tine, cu contextul pe care clientul nu-l are."""
    items = ''.join(f'<li>{escape(x)}</li>' for x in list_problems(result))
    html = f'''<div style="font-family:Arial,sans-serif">
      <h3>Problema: {escape(name)}</h3>
      <p><b>Domeniu:</b> {escape(domain)}<br>
      <b>Plan:</b> {escape(plan)}<br>
      <b>Scor:</b> {result['score']}/100<br>
      <b>Email client:</b> {escape(client_email)}</p>
      <ul>{items}</ul>
      <p><b>Clientul:</b> {escape(client_note)}.</p>
      <p>Daca e cazul, contacteaza-l si propune remedierea.</p>
    </div>'''
    send_html(OWNER_EMAIL, f'[INTERN] {name} ({domain}) - scor {result["score"]}/100 - plan {plan}', html)

def send_premium_notice(domain, client_email):
    """Mesaj calm, o singura data pe incident, pentru clientii Premium."""
    html = f'''<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
      <div style="background:#0a0e1a;padding:28px;text-align:center;">
        <div style="font-size:26px;font-weight:700;color:#ffffff;">Cyber<span style="color:#3b82f6;">Shield</span></div>
        <div style="color:#94a3b8;font-size:14px;margin-top:6px;">Security Update</div>
      </div>
      <div style="background:#f8fafc;padding:28px;">
        <div style="background:#3b82f6;color:#ffffff;border-radius:10px;padding:24px;text-align:center;">
          <div style="font-size:20px;font-weight:700;">We detected an issue and we are looking into it</div>
          <div style="margin-top:6px;">Domain: {escape(domain)}</div>
        </div>
        <p style="color:#334155;margin-top:20px;">As a Premium client, you do not need to do anything right now. We will confirm as soon as it is resolved. If we need access to your hosting panel, we will contact you directly.</p>
        <p style="color:#64748b;font-size:13px;margin-top:24px;">CyberShield &mdash; Automated Security Monitoring</p>
      </div>
    </div>'''
    send_html(client_email, f'[CyberShield] We are looking into an issue - {domain}', html)

def send_resolved(name, domain, plan, client_email, prev_result, new_result, prev_score, new_score):
    """Confirmare cu bifa verde si lista problemelor rezolvate, catre client si catre tine."""
    try:
        new_keys = {k for k, _, _ in find_problems(new_result)}
        fixed = [(ro, en) for k, ro, en in find_problems(prev_result) if k not in new_keys]
    except Exception:
        fixed = []
    if not fixed:
        fixed = [('Scorul era sub nivelul sigur', 'Your security score was below the safe level')]

    items_en = ''.join(f'<li style="margin-bottom:6px;">&#9989; {escape(en)}</li>' for _, en in fixed)
    items_ro = ''.join(f'<li>{escape(ro)}</li>' for ro, _ in fixed)

    client_html = f'''<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
      <div style="background:#0a0e1a;padding:28px;text-align:center;">
        <div style="font-size:26px;font-weight:700;color:#ffffff;">Cyber<span style="color:#3b82f6;">Shield</span></div>
        <div style="color:#94a3b8;font-size:14px;margin-top:6px;">Security Update</div>
      </div>
      <div style="background:#f8fafc;padding:28px;">
        <div style="background:#10b981;color:#ffffff;border-radius:10px;padding:24px;text-align:center;">
          <div style="font-size:38px;line-height:1;">&#9989;</div>
          <div style="font-size:20px;font-weight:700;margin-top:8px;">All issues resolved</div>
          <div style="margin-top:6px;">Domain: {escape(domain)}</div>
        </div>
        <p style="color:#0f172a;font-weight:700;margin-top:20px;margin-bottom:8px;">What was fixed:</p>
        <ul style="list-style:none;padding:0;margin:0;color:#334155;">{items_en}</ul>
        <p style="font-size:16px;color:#0f172a;margin-top:20px;">Security score: <b>{prev_score}/100 &rarr; {new_score}/100</b></p>
        <p style="color:#334155;">Our latest scan found no remaining problems. Monitoring continues as usual.</p>
        <p style="color:#64748b;font-size:13px;margin-top:24px;">CyberShield &mdash; Automated Security Monitoring</p>
      </div>
    </div>'''
    send_html(client_email, f'[CyberShield] \u2705 All issues resolved - {domain}', client_html)

    owner_html = f'''<div style="font-family:Arial,sans-serif">
      <h3 style="color:#059669;">&#9989; Rezolvat: {escape(name)}</h3>
      <p><b>Domeniu:</b> {escape(domain)}<br>
      <b>Plan:</b> {escape(plan)}<br>
      <b>Scor:</b> {prev_score}/100 &rarr; {new_score}/100<br>
      <b>Email client:</b> {escape(client_email)}</p>
      <p><b>Probleme rezolvate:</b></p>
      <ul>{items_ro}</ul>
      <p>Clientul a primit confirmarea.</p>
    </div>'''
    send_html(OWNER_EMAIL, f'[INTERN] \u2705 {name} ({domain}) - rezolvat, scor {prev_score} -> {new_score}', owner_html)

def run_all_scans():
    print(f'\n[CyberShield] Starting scans — {datetime.utcnow()}')
    clients = get_all_clients()

    if not clients:
        print('No clients found in database.')
        return

    print(f'Found {len(clients)} client(s).\n')

    for client in clients:
        client_id, name, domain, email, plan = client

        if not should_scan_today(plan):
            print(f'Skipping {name} ({domain}) — plan {plan} not scheduled today')
            continue

        print(f'Scanning {name} ({domain}) — Plan: {plan}...')

        try:
            # Scanarea anterioara, citita INAINTE sa salvam cea noua
            prev = get_last_scan(client_id)
            prev_score = prev[0] if prev else None

            result = scan(domain)
            save_scan(client_id, domain, result['score'], result['ports'], result['ssl'], result['blacklist'])

            if result['score'] < ALERT_THRESHOLD:
                if plan == 'premium':
                    first_detection = prev_score is None or prev_score >= ALERT_THRESHOLD
                    if first_detection:
                        print(f'Score {result["score"]} — first detection, sending calm notice to {email}')
                        send_premium_notice(domain, email)
                        client_note = 'a primit mesajul calm (prima detectare)'
                    else:
                        print(f'Score {result["score"]} — problem still open, client already informed, notifying owner only')
                        client_note = 'nu a primit nimic acum (a primit deja mesajul calm)'
                else:
                    print(f'Score {result["score"]} — sending alert to {email}')
                    send_alert(email, domain, result)
                    client_note = 'a primit alerta'
                notify_owner(name, domain, plan, email, result, client_note)
            elif prev_score is not None and prev_score < ALERT_THRESHOLD:
                print(f'Score {result["score"]} — problems resolved (was {prev_score}), sending confirmation')
                prev_result = {'ports': prev[1], 'ssl': prev[2], 'blacklist': prev[3]}
                send_resolved(name, domain, plan, email, prev_result, result, prev_score, result['score'])
            else:
                print(f'Score {result["score"]} — OK, no alert needed')
        except Exception as e:
            print(f'Error scanning {domain}: {e}')

    print(f'\n[CyberShield] All scans complete — {datetime.utcnow()}')

if __name__ == '__main__':
    run_all_scans()