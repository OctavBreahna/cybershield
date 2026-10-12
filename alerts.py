import os
import json
from mailer import send_checked
from dotenv import load_dotenv

load_dotenv()

SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
FROM_EMAIL = os.getenv('FROM_EMAIL', 'octav.breahna1950@gmail.com')

def send_alert(to_email, domain, scan_result):
    score = scan_result.get('score', 0)
    
    if score >= 90:
        severity = 'LOW'
        color = '#10b981'
    elif score >= 70:
        severity = 'MEDIUM'
        color = '#f59e0b'
    elif score >= 40:
        severity = 'HIGH'
        color = '#ef4444'
    else:
        severity = 'CRITICAL'
        color = '#7f1d1d'

    open_ports = [p for p in scan_result.get('ports', []) if p['state'] == 'open']
    ssl = scan_result.get('ssl', {})
    blacklist = scan_result.get('blacklist', {})

    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #0a0e1a; padding: 24px; text-align: center;">
            <h1 style="color: white; margin: 0;">Cyber<span style="color: #3b82f6;">Shield</span></h1>
            <p style="color: #94a3b8; margin: 4px 0;">Security Alert</p>
        </div>
        <div style="padding: 24px; background: #f8fafc;">
            <div style="background: {color}; color: white; padding: 16px; border-radius: 8px; text-align: center; margin-bottom: 24px;">
                <h2 style="margin: 0;">Security Score: {score}/100 — {severity}</h2>
                <p style="margin: 4px 0;">Domain: {domain}</p>
            </div>
            <h3>Issues Found:</h3>
            <ul>
    """

    if open_ports:
        dangerous = [21, 23, 3306, 5432]
        for p in open_ports:
            if p['port'] in dangerous:
                html += f"<li style='color: red;'>⚠️ Dangerous port {p['port']} is open!</li>"

    if not ssl.get('valid'):
        html += f"<li style='color: red;'>⚠️ SSL certificate is invalid or expired!</li>"
    elif ssl.get('days_left', 999) < 30:
        html += f"<li style='color: orange;'>⚠️ SSL certificate expires in {ssl['days_left']} days!</li>"

    if blacklist.get('blacklisted'):
        html += "<li style='color: red;'>🚨 Domain is blacklisted by Google!</li>"

    html += """
            </ul>
            <p style="color: #64748b; font-size: 12px;">CyberShield — Automated Security Monitoring</p>
        </div>
    </div>
    """

    return send_checked(to_email, f"[CyberShield] Security Alert — {domain} — Score: {score}/100", html)

if __name__ == '__main__':
    test_result = {
        'score': 60,
        'ports': [{'port': 21, 'state': 'open'}, {'port': 443, 'state': 'open'}],
        'ssl': {'valid': False, 'error': 'expired'},
        'blacklist': {'blacklisted': False}
    }
    send_alert('octav.breahna1950@gmail.com', 'testdomain.com', test_result)
