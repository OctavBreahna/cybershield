"""Email-rezumat zilnic, doar pentru tine (cybersh.official@gmail.com).

Arata starea tuturor clientilor activi si te avertizeaza daca ceva nu mai ruleaza
(scanari intarziate, control orar oprit). Clientii nu primesc nimic de aici.
"""
import json
import os
from datetime import datetime, timedelta, timezone
from html import escape

from database import get_connection, get_all_clients
from hourly_watch import ISSUE_ORDER, ISSUE_LABELS
from mailer import OWNER_EMAIL, send_checked

try:
    from zoneinfo import ZoneInfo
    LOCAL_TZ = ZoneInfo('Europe/Chisinau')
except Exception:
    LOCAL_TZ = timezone.utc

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'daily_summary_state.json')

ALERT_THRESHOLD = 90
# cat de veche poate fi ultima scanare programata, pe plan, inainte sa te avertizam
MAX_SCAN_AGE = {'premium': timedelta(hours=5), 'standard': timedelta(hours=26), 'basic': timedelta(days=8)}
MAX_WATCH_AGE = timedelta(hours=2)

STATUS_RO = {'ok': 'ok', 'warning': 'avertisment', 'problem': 'problemă'}
STATUS_COLOR = {'ok': '#059669', 'warning': '#d97706', 'problem': '#dc2626'}
STATUS_ICON = {'ok': '\u2705', 'warning': '\u26a0\ufe0f', 'problem': '\U0001f534'}


def age_text(dt, now):
    secs = max(0, int((now - dt).total_seconds()))
    if secs < 3600:
        return f'{secs // 60} min'
    if secs < 48 * 3600:
        return f'{secs // 3600} h'
    return f'{secs // 86400} zile'


def local_text(dt):
    return dt.replace(tzinfo=timezone.utc).astimezone(LOCAL_TZ).strftime('%d.%m %H:%M')


def query_one(conn, cur, sql, params=()):
    """Un rand sau None. Daca tabela lipseste sau interogarea esueaza, nu strica rezumatul."""
    try:
        cur.execute(sql, params)
        return cur.fetchone()
    except Exception:
        conn.rollback()
        return None


def client_status(conn, cur, client, now):
    cid, name, domain, email, plan = client
    problems, notes = [], []

    scan = query_one(conn, cur,
                     'SELECT scanned_at, score FROM scans WHERE client_id = %s ORDER BY scanned_at DESC LIMIT 1',
                     (cid,))
    if scan is None:
        scan_text = 'nicio scanare încă'
        notes.append('nicio scanare încă')
    else:
        scanned_at, score = scan
        scan_text = f'{score}/100 · {local_text(scanned_at)} (acum {age_text(scanned_at, now)})'
        if score < ALERT_THRESHOLD:
            problems.append(f'scor {score}/100')
        if now - scanned_at > MAX_SCAN_AGE.get(plan, timedelta(days=8)):
            notes.append(f'ultima scanare e veche ({age_text(scanned_at, now)}); verifică cron-ul')

    state = query_one(conn, cur, 'SELECT confirmed FROM watch_state WHERE client_id = %s', (cid,))
    confirmed = [k for k in ISSUE_ORDER if k in (state[0] if state and state[0] else '').split(',')]
    for k in confirmed:
        problems.append(ISSUE_LABELS[k])

    watch = query_one(conn, cur,
                      'SELECT checked_at, issues, http_status, ssl_state, ssl_days_left FROM watch_checks '
                      'WHERE client_id = %s ORDER BY checked_at DESC LIMIT 1', (cid,))
    if watch is None:
        watch_text = '—'
    else:
        checked_at, issues, http_status, ssl_state, ssl_days = watch
        http = f'HTTP {http_status}' if http_status else 'fără răspuns'
        ssl_txt = f'SSL {ssl_state}' + (f' {ssl_days} zile' if ssl_days is not None else '')
        pending = bool(issues) and set(issues.split(',')) != set(confirmed)
        watch_text = f'{http} · {ssl_txt} · acum {age_text(checked_at, now)}' + (' (în confirmare)' if pending else '')

    status = 'problem' if problems else ('warning' if notes else 'ok')
    return {'id': cid, 'name': name, 'domain': domain, 'plan': plan, 'status': status,
            'scan_text': scan_text, 'watch_text': watch_text, 'problems': problems, 'notes': notes}


def system_lines(conn, cur, now):
    """(nivel, text) pentru starea sistemului, nu a clientilor."""
    row = query_one(conn, cur, 'SELECT MAX(checked_at) FROM watch_checks')
    last = row[0] if row else None
    if last is None:
        return [('warning', 'Controlul orar nu a rulat niciodată (verifică linia din cron).')]
    if now - last > MAX_WATCH_AGE:
        return [('warning', f'Controlul orar nu a mai rulat de {age_text(last, now)} (verifică cron-ul).')]
    return [('ok', f'Controlul orar rulează (ultima verificare acum {age_text(last, now)}).')]


def load_previous():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return None


def save_current(rows):
    with open(STATE_FILE, 'w') as f:
        json.dump({str(r['id']): r['status'] for r in rows}, f)


def changes_since_yesterday(rows, previous):
    if previous is None:
        return []
    out = []
    for r in rows:
        before = previous.get(str(r['id']))
        if before is None:
            out.append(f"{r['name']}: client nou ({STATUS_RO[r['status']]})")
        elif before != r['status']:
            out.append(f"{r['name']}: {STATUS_RO[before]} → {STATUS_RO[r['status']]}")
    return out


def build_email(rows, sys_lines, changes, now):
    n_problem = sum(1 for r in rows if r['status'] == 'problem')
    n_warning = sum(1 for r in rows if r['status'] == 'warning') + sum(1 for lvl, _ in sys_lines if lvl != 'ok')

    if n_problem:
        subject = f'[ZILNIC] {STATUS_ICON["problem"]} {n_problem} client(i) cu probleme'
    elif n_warning:
        subject = f'[ZILNIC] {STATUS_ICON["warning"]} {n_warning} avertisment(e)'
    elif rows:
        subject = f'[ZILNIC] {STATUS_ICON["ok"]} Totul în regulă · {len(rows)} client(i)'
    else:
        subject = '[ZILNIC] Nu există clienți activi'

    parts = [f'<h2 style="margin:0 0 4px;">Rezumat zilnic CyberShield</h2>',
             f'<p style="color:#64748b;margin:0 0 16px;">{local_text(now)} (ora Moldovei) · {len(rows)} client(i) activi</p>']

    sys_html = ''.join(
        f'<li style="color:{STATUS_COLOR[lvl]};">{STATUS_ICON[lvl]} {escape(text)}</li>' for lvl, text in sys_lines)
    parts.append(f'<p style="margin:0 0 4px;"><b>Sistem</b></p><ul style="margin:0 0 16px;padding-left:20px;">{sys_html}</ul>')

    if changes:
        items = ''.join(f'<li>{escape(c)}</li>' for c in changes)
        parts.append(f'<p style="margin:0 0 4px;"><b>Schimbări față de ieri</b></p>'
                     f'<ul style="margin:0 0 16px;padding-left:20px;">{items}</ul>')

    for r in rows:
        color = STATUS_COLOR[r['status']]
        detail = ''.join(f'<div style="color:{STATUS_COLOR["problem"]};">• {escape(p)}</div>' for p in r['problems'])
        detail += ''.join(f'<div style="color:{STATUS_COLOR["warning"]};">• {escape(n)}</div>' for n in r['notes'])
        parts.append(
            f'<div style="border-left:4px solid {color};background:#f8fafc;padding:10px 14px;margin:0 0 10px;">'
            f'<div><b>{STATUS_ICON[r["status"]]} {escape(r["name"])}</b> '
            f'<span style="color:#64748b;">· {escape(r["domain"])} · {escape(r["plan"])}</span></div>'
            f'<div style="color:#334155;font-size:13px;">Ultima scanare: {escape(r["scan_text"])}</div>'
            f'<div style="color:#334155;font-size:13px;">Control orar: {escape(r["watch_text"])}</div>'
            f'{detail}</div>')

    parts.append('<p style="color:#64748b;font-size:12px;">Rezumatul vine zilnic. Dacă într-o zi nu primești nimic, '
                 'verifică serverul (cron-ul rulează pe el).</p>')
    html = '<div style="font-family:Arial,sans-serif;max-width:640px;">' + ''.join(parts) + '</div>'
    return subject, html


def main():
    now = datetime.utcnow()
    conn = get_connection()
    cur = conn.cursor()
    clients = get_all_clients()
    rows = [client_status(conn, cur, c, now) for c in clients]
    sys_lines = system_lines(conn, cur, now)
    cur.close()
    conn.close()

    changes = changes_since_yesterday(rows, load_previous())
    subject, html = build_email(rows, sys_lines, changes, now)

    if send_checked(OWNER_EMAIL, subject, html):
        save_current(rows)
        print(f'[ZILNIC] {now:%Y-%m-%d %H:%M} trimis: {subject}')
    else:
        print('[ZILNIC] Emailul nu a plecat; reincerc la urmatoarea rulare.')


if __name__ == '__main__':
    main()