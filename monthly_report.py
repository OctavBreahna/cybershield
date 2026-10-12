import os
from datetime import datetime
from database import get_all_clients
from report import generate_report
from mailer import send_checked
from dotenv import load_dotenv

load_dotenv()


def send_report_email(client_email, client_name, pdf_path, domain):
    """Trimite raportul lunar cu PDF atasat. Returneaza True doar daca emailul a fost acceptat."""
    with open(pdf_path, 'rb') as f:
        pdf_bytes = f.read()

    month_str = datetime.now().strftime("%B %Y")
    subject = f'CyberShield — Security Report {month_str} for {domain}'
    html = f'''
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0f172a;color:#e2e8f0;padding:32px;border-radius:12px;">
            <h1 style="color:#3b82f6;margin-bottom:8px;">CyberShield</h1>
            <p style="color:#94a3b8;margin-bottom:24px;">Monthly Security Report</p>
            <p>Dear <b>{client_name}</b>,</p>
            <p>Please find attached your monthly security report for <b>{domain}</b> — {month_str}.</p>
            <p>The report includes:</p>
            <ul>
                <li>Security score (0-100)</li>
                <li>SSL certificate status</li>
                <li>Open ports analysis</li>
                <li>Blacklist check</li>
                <li>Security recommendations</li>
            </ul>
            <p style="margin-top:24px;">For questions or urgent issues, contact us at <a href="mailto:alerts@cybersh.tech" style="color:#3b82f6;">alerts@cybersh.tech</a></p>
            <hr style="border-color:#1e293b;margin:24px 0;">
            <p style="color:#475569;font-size:12px;">CyberShield — cybersh.tech</p>
        </div>
        '''

    return send_checked(client_email, subject, html,
                        attachments=[(os.path.basename(pdf_path), pdf_bytes)])


def run_monthly_reports():
    print(f"[CyberShield] Monthly reports started — {datetime.now()}")
    clients = get_all_clients()

    if not clients:
        print("[WARNING] No active clients found.")
        return

    for client in clients:
        client_id, name, domain, email, plan = client
        print(f"[→] Generating report for {name} ({domain})...")
        try:
            pdf_path = generate_report(client_id=client_id)
            if not pdf_path:
                print(f"[ERROR] Could not generate report for {domain}")
                continue

            if send_report_email(email, name, pdf_path, domain):
                print(f"[OK] Report sent to {email} for {domain}")
            else:
                print(f"[ERROR] Report email NOT sent to {email} for {domain}")
        except Exception as e:
            print(f"[ERROR] {domain}: {e}")

    print(f"[CyberShield] Monthly reports complete — {datetime.now()}")


if __name__ == "__main__":
    run_monthly_reports()