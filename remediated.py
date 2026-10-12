"""Confirmarea remedierii, declansata de tine.

Utilizare:
    python3 remediated.py domeniu.md --note "Am reinnoit certificatul SSL"
    python3 remediated.py domeniu.md --id 7      (daca mai multi clienti au acelasi domeniu)

Scaneaza clientul pe loc. Daca scorul e >= 90, clientul primeste emailul "We fixed it"
iar tu primesti [INTERN]. Daca scorul e sub 90, nu trimite nimic si iti arata ce a ramas.
"""
import argparse
import sys
from html import escape

import run_all_scans as ras
from scanner import scan
from database import get_connection, save_scan, get_last_scan
from mailer import OWNER_EMAIL, send_checked


def find_clients(domain):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, name, domain, email, plan FROM clients WHERE domain = %s AND active = TRUE ORDER BY id',
                (domain,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def client_html(domain, note, fixed_en, prev_score, new_score):
    items = ''.join(f'<li style="margin-bottom:6px;">&#9989; {escape(x)}</li>' for x in fixed_en)
    note_block = ''
    if note:
        note_html = escape(note).replace('\n', '<br>')
        note_block = (f'<p style="color:#0f172a;font-weight:700;margin:20px 0 6px;">What we did:</p>'
                      f'<p style="color:#334155;margin:0;">{note_html}</p>')
    return f'''<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
      <div style="background:#0a0e1a;padding:28px;text-align:center;">
        <div style="font-size:26px;font-weight:700;color:#ffffff;">Cyber<span style="color:#3b82f6;">Shield</span></div>
        <div style="color:#94a3b8;font-size:14px;margin-top:6px;">Security Update</div>
      </div>
      <div style="background:#f8fafc;padding:28px;">
        <div style="background:#10b981;color:#ffffff;border-radius:10px;padding:24px;text-align:center;">
          <div style="font-size:38px;line-height:1;">&#9989;</div>
          <div style="font-size:20px;font-weight:700;margin-top:8px;">We fixed it</div>
          <div style="margin-top:6px;">Domain: {escape(domain)}</div>
        </div>
        {note_block}
        <p style="color:#0f172a;font-weight:700;margin:20px 0 8px;">What was fixed:</p>
        <ul style="list-style:none;padding:0;margin:0;color:#334155;">{items}</ul>
        <p style="font-size:16px;color:#0f172a;margin-top:20px;">Security score: <b>{prev_score}/100 &rarr; {new_score}/100</b></p>
        <p style="color:#334155;">We re-scanned your domain after the fix and found no remaining problems. Monitoring continues as usual.</p>
        <p style="color:#64748b;font-size:13px;margin-top:24px;">CyberShield &mdash; Automated Security Monitoring</p>
      </div>
    </div>'''


def owner_html(name, domain, plan, email, note, fixed_ro, prev_score, new_score):
    items = ''.join(f'<li>{escape(x)}</li>' for x in fixed_ro)
    note_line = f'<p><b>Nota ta:</b> {escape(note)}</p>' if note else ''
    return f'''<div style="font-family:Arial,sans-serif">
      <h3 style="color:#059669;">&#9989; Remediat: {escape(name)}</h3>
      <p><b>Domeniu:</b> {escape(domain)}<br>
      <b>Plan:</b> {escape(plan)}<br>
      <b>Scor:</b> {prev_score}/100 &rarr; {new_score}/100<br>
      <b>Email client:</b> {escape(email)}</p>
      {note_line}
      <p><b>Probleme rezolvate:</b></p>
      <ul>{items}</ul>
      <p>Clientul a primit emailul "We fixed it".</p>
    </div>'''


def main():
    parser = argparse.ArgumentParser(description='Confirma o remediere si trimite emailul clientului.')
    parser.add_argument('domain')
    parser.add_argument('--note', '-n', default='', help='ce ai facut (apare in emailul clientului)')
    parser.add_argument('--id', type=int, default=None, help='ID client, daca domeniul apare de mai multe ori')
    args = parser.parse_args()

    domain = args.domain.strip().lower().replace('https://', '').replace('http://', '').strip('/')
    clients = find_clients(domain)
    if args.id is not None:
        clients = [c for c in clients if c[0] == args.id]
    if not clients:
        print(f'Niciun client activ cu domeniul {domain}.')
        sys.exit(1)
    if len(clients) > 1:
        print(f'Mai multi clienti activi cu domeniul {domain}: ' +
              ', '.join(f'ID {c[0]} ({c[1]})' for c in clients) + '. Foloseste --id.')
        sys.exit(1)

    client_id, name, domain, email, plan = clients[0]

    prev = get_last_scan(client_id)
    if prev is None:
        print('Nu exista nicio scanare anterioara pentru acest client. Nu trimit nimic.')
        sys.exit(1)
    prev_score = prev[0]
    if prev_score >= ras.ALERT_THRESHOLD:
        print(f'Ultima scanare are scorul {prev_score} (>= {ras.ALERT_THRESHOLD}): nicio problema deschisa. '
              f'Nu trimit nimic.')
        sys.exit(0)

    print(f'Scanez {domain} (dureaza ~30-40 secunde)...')
    result = scan(domain)
    new_score = result['score']

    if new_score < ras.ALERT_THRESHOLD:
        save_scan(client_id, domain, new_score, result['ports'], result['ssl'], result['blacklist'])
        print(f'Scor dupa remediere: {new_score} (sub {ras.ALERT_THRESHOLD}). Mai sunt probleme deschise:')
        for p in ras.list_problems(result):
            print(f'  - {p}')
        print('Nu trimit nimic clientului.')
        sys.exit(0)

    prev_result = {'ports': prev[1], 'ssl': prev[2], 'blacklist': prev[3]}
    try:
        new_keys = {k for k, _, _ in ras.find_problems(result)}
        fixed = [(ro, en) for k, ro, en in ras.find_problems(prev_result) if k not in new_keys]
    except Exception:
        fixed = []
    if not fixed:
        fixed = [('Scorul era sub nivelul sigur', 'Your security score was below the safe level')]
    fixed_ro = [ro for ro, _ in fixed]
    fixed_en = [en for _, en in fixed]

    sent = send_checked(email, f'[CyberShield] \u2705 Fixed - {domain}',
                        client_html(domain, args.note, fixed_en, prev_score, new_score))
    if not sent:
        print('Emailul catre client NU a plecat. Rezultatul scanarii nu a fost salvat; poti rula din nou comanda.')
        sys.exit(1)

    save_scan(client_id, domain, new_score, result['ports'], result['ssl'], result['blacklist'])
    send_checked(OWNER_EMAIL, f'[INTERN] \u2705 {name} ({domain}) - remediat, scor {prev_score} -> {new_score}',
                 owner_html(name, domain, plan, email, args.note, fixed_ro, prev_score, new_score))
    print(f'Gata. Scor {prev_score} -> {new_score}. Clientul ({email}) a primit emailul "We fixed it".')
    print('Probleme rezolvate: ' + ', '.join(fixed_ro))


if __name__ == '__main__':
    main()