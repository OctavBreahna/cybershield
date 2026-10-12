import sys
from database import get_connection, add_client, save_scan
from scanner import scan
from report import generate_report
from monthly_report import send_report_email

def scan_and_send(company_name, domain, email, plan='basic'):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT id FROM clients WHERE domain = %s", (domain,))
    existing = cur.fetchone()

    if existing:
        client_id = existing[0]
        print(f"[i] Client existent gasit — ID {client_id}")
    else:
        client_id = add_client(company_name, domain, email, plan)
        print(f"[i] Client nou creat — ID {client_id}")

    cur.close()
    conn.close()

    print(f"\n[1/3] Scanare {domain}...")
    result = scan(domain)
    save_scan(client_id, result['domain'], result['score'], result['ports'], result['ssl'], result['blacklist'])

    print(f"\n[2/3] Generare raport PDF...")
    pdf_path = generate_report(client_id=client_id)
    if not pdf_path:
        print("[EROARE] Raportul nu a putut fi generat.")
        return

    print(f"\n[3/3] Trimitere email catre {email}...")
    status = send_report_email(email, company_name, pdf_path, domain)

    if status in (202, True):
        print(f"\nGata! Scor: {result['score']}/100 — raport trimis la {email}")
    else:
        print(f"\nEmail status neasteptat: {status}")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Utilizare: python3 scan_client.py \"Numele Companiei\" domeniu.md email@client.com [plan]")
        sys.exit(1)
    scan_and_send(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else 'basic')