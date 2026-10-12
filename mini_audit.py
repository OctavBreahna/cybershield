from database import get_connection
from datetime import datetime, timedelta

def mini_audit_checklist():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, name, domain, plan FROM clients
        WHERE active = TRUE AND plan IN ('standard', 'premium')
        ORDER BY name
    """)
    clients = cur.fetchall()

    if not clients:
        print("Niciun client Standard/Premium activ momentan.")
        return

    print("=" * 60)
    print("MINI-AUDIT LUNAR - " + datetime.now().strftime("%B %Y"))
    print("=" * 60)

    for client_id, name, domain, plan in clients:
        print(f"\n-- {name} ({domain}) - plan {plan.upper()} --")

        cur.execute("""
            SELECT score, ssl, scanned_at FROM scans
            WHERE client_id = %s AND scanned_at > %s
            ORDER BY scanned_at ASC
        """, (client_id, datetime.now() - timedelta(days=30)))
        scans = cur.fetchall()

        if scans:
            scores = [s[0] for s in scans]
            print(f"  Scanari in ultima luna: {len(scores)}")
            print(f"  Scor: min {min(scores)} | max {max(scores)} | ultimul {scores[-1]}")
            if max(scores) - min(scores) >= 15:
                print("  ATENTIE: fluctuatie mare de scor, verifica de ce")
            last_ssl = scans[-1][1]
            if isinstance(last_ssl, dict) and last_ssl.get('days_left') is not None:
                print(f"  SSL: expira peste {last_ssl['days_left']} zile")
        else:
            print("  ATENTIE: nicio scanare in ultima luna, verifica scannerul")

        print("  [ ] Verificat vizual site-ul")
        print("  [ ] Verificata data de expirare a domeniului")
        print("  [ ] Scrisa o nota personala pentru raportul lunii")

    cur.close()
    conn.close()

if __name__ == "__main__":
    mini_audit_checklist()
    