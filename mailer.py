import os
import sys
import base64
import requests
from dotenv import load_dotenv

load_dotenv()

# Aici primesti tu notificarile interne
OWNER_EMAIL = 'cybersh.official@gmail.com'

RESEND_URL = 'https://api.resend.com/emails'


def _from_address():
    addr = os.getenv('FROM_EMAIL', 'alerts@cybersh.tech')
    return addr if '<' in addr else f'CyberShield <{addr}>'


def _send_resend(to_email, subject, html, attachments):
    key = os.getenv('RESEND_API_KEY')
    if not key:
        print('[mailer] RESEND_API_KEY lipseste din .env')
        return False
    payload = {
        'from': _from_address(),
        'to': [to_email],
        'subject': subject,
        'html': html,
    }
    if attachments:
        payload['attachments'] = [
            {'filename': name, 'content': base64.b64encode(data).decode()}
            for name, data in attachments
        ]
    try:
        r = requests.post(
            RESEND_URL,
            headers={
                'Authorization': f'Bearer {key}',
                'Content-Type': 'application/json',
                'User-Agent': 'cybershield-mailer/1.0',
            },
            json=payload,
            timeout=30,
        )
        if 200 <= r.status_code < 300:
            return True
        print(f'[mailer] Resend a refuzat emailul catre {to_email}: {r.status_code} {r.text[:300]}')
        return False
    except Exception as e:
        print(f'[mailer] Eroare Resend catre {to_email}: {e}')
        return False


def _send_sendgrid(to_email, subject, html, attachments):
    key = os.getenv('SENDGRID_API_KEY')
    if not key:
        return False
    try:
        import sendgrid
        from sendgrid.helpers.mail import (Mail, Attachment, FileContent,
                                           FileName, FileType, Disposition)
        message = Mail(
            from_email=os.getenv('FROM_EMAIL', 'alerts@cybersh.tech'),
            to_emails=to_email,
            subject=subject,
            html_content=html,
        )
        for name, data in (attachments or []):
            message.add_attachment(Attachment(
                FileContent(base64.b64encode(data).decode()),
                FileName(name),
                FileType('application/pdf' if name.lower().endswith('.pdf') else 'application/octet-stream'),
                Disposition('attachment'),
            ))
        response = sendgrid.SendGridAPIClient(api_key=key).send(message)
        return 200 <= response.status_code < 300
    except Exception as e:
        print(f'[mailer] Eroare SendGrid catre {to_email}: {e}')
        return False


def send_checked(to_email, subject, html, attachments=None):
    """Trimite un email. Returneaza True doar daca a fost acceptat.

    Intai prin Resend; daca Resend esueaza, incearca SendGrid (plasa de
    siguranta pana pe 29 nov.). attachments = lista de (nume_fisier, bytes).
    """
    if _send_resend(to_email, subject, html, attachments):
        return True
    if _send_sendgrid(to_email, subject, html, attachments):
        print(f'[mailer] Trimis prin SendGrid (rezerva) catre {to_email}')
        return True
    return False


if __name__ == '__main__':
    # Test: python3 mailer.py --test  -> trimite DOAR prin Resend catre OWNER_EMAIL
    if '--test' in sys.argv:
        ok = _send_resend(
            OWNER_EMAIL,
            'Test Resend - CyberShield',
            '<p>Test trimis prin <b>Resend</b> de pe serverul cybersh-prod.</p>',
            [('test.txt', b'Atasament de test CyberShield')],
        )
        print('OK - Resend a acceptat emailul' if ok else 'ESEC - vezi mesajul de mai sus')
    else:
        print('Foloseste: python3 mailer.py --test')