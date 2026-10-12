import os
import subprocess
from database import get_db_connection
from dotenv import load_dotenv

load_dotenv()

VPN_DIR = "/etc/wireguard"
SERVER_IP = "108.61.178.187"
VPN_SUBNET = "10.0.0"
SERVER_PORT = 51820

def run(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip()

def init_server():
    import os as _os
    if _os.path.exists('/etc/wireguard/wg0.conf'):
        print('[CyberShield] wg0.conf exista deja: nu reinitializez serverul VPN (ar strica toti peers).')
        return
    os.makedirs(VPN_DIR, exist_ok=True)
    priv_key, _ = run("wg genkey")
    pub_key, _ = run(f"echo '{priv_key}' | wg pubkey")

    config = f"""[Interface]
PrivateKey = {priv_key}
Address = {VPN_SUBNET}.1/24
ListenPort = {SERVER_PORT}
PostUp = iptables -I FORWARD 1 -i wg0 -o wg0 -j DROP; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o enp1s0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -o wg0 -j DROP; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o enp1s0 -j MASQUERADE
"""
    with open(f"{VPN_DIR}/wg0.conf", "w") as f:
        f.write(config)

    with open(f"{VPN_DIR}/server_keys.txt", "w") as f:
        f.write(f"PRIVATE={priv_key}\nPUBLIC={pub_key}\n")

    run("systemctl enable wg-quick@wg0")
    run("systemctl start wg-quick@wg0")
    print(f"[CyberShield] VPN server initialized. Public key: {pub_key}")
    return pub_key

def get_server_pubkey():
    try:
        with open(f"{VPN_DIR}/server_keys.txt") as f:
            for line in f:
                if line.startswith("PUBLIC="):
                                       return line.strip().split("=", 1)[1]
    except:
        return None

def get_next_ip():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT ip_address FROM vpn_peers")
    rows = cur.fetchall()
    cur.close(); conn.close()
    used = []
    for (ip,) in rows:
        try:
            used.append(int(ip.split('.')[-1]))
        except Exception:
            pass
    next_octet = max(used, default=1) + 1
    return f"{VPN_SUBNET}.{next_octet}"

def init_vpn_table():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vpn_peers (
            id SERIAL PRIMARY KEY,
            client_id INTEGER REFERENCES clients(id),
            peer_name VARCHAR(255),
            private_key TEXT,
            public_key TEXT,
            ip_address VARCHAR(50),
            config TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    conn.commit()
    cur.close(); conn.close()
    print("[CyberShield] VPN table ready.")

def add_peer(client_id, peer_name, allowed_ips=None):
    if allowed_ips is None:
        allowed_ips = f"{VPN_SUBNET}.0/24"  # implicit: doar reteaua VPN interna, nu tot internetul
    priv_key, _ = run("wg genkey")
    pub_key, _ = run(f"echo '{priv_key}' | wg pubkey")
    peer_ip = get_next_ip()
    server_pubkey = get_server_pubkey()

    peer_config = f"""[Interface]
PrivateKey = {priv_key}
Address = {peer_ip}/24
DNS = 1.1.1.1

[Peer]
PublicKey = {server_pubkey}
Endpoint = {SERVER_IP}:{SERVER_PORT}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO vpn_peers (client_id, peer_name, private_key, public_key, ip_address, config)
        VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
    """, (client_id, peer_name, priv_key, pub_key, peer_ip, peer_config))
    peer_id = cur.fetchone()[0]
    conn.commit()
    cur.close(); conn.close()

    run(f"wg set wg0 peer {pub_key} allowed-ips {peer_ip}/32")
    run("wg-quick save wg0")

    config_path = f"/home/cybersh/vpn_configs/{client_id}_{peer_name}.conf"
    os.makedirs("/home/cybersh/vpn_configs", exist_ok=True)
    with open(config_path, "w") as f:
        f.write(peer_config)

    print(f"[CyberShield] Peer {peer_name} added — IP: {peer_ip}")
    return {"peer_id": peer_id, "ip": peer_ip, "config_path": config_path, "config": peer_config}

def remove_peer(client_id, peer_name):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT public_key FROM vpn_peers WHERE client_id = %s AND peer_name = %s",
                (client_id, peer_name))
    row = cur.fetchone()
    if not row:
        print(f"[ERROR] Peer {peer_name} not found.")
        return False
    pub_key = row[0]
    run(f"wg set wg0 peer {pub_key} remove")
    run("wg-quick save wg0")
    cur.execute("DELETE FROM vpn_peers WHERE client_id = %s AND peer_name = %s",
                (client_id, peer_name))
    conn.commit()
    cur.close(); conn.close()
    print(f"[CyberShield] Peer {peer_name} removed.")
    return True

def list_peers(client_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT peer_name, ip_address, created_at FROM vpn_peers WHERE client_id = %s",
                (client_id,))
    peers = cur.fetchall()
    cur.close(); conn.close()
    return [{"name": p[0], "ip": p[1], "created_at": str(p[2])} for p in peers]

if __name__ == "__main__":
    init_vpn_table()
    init_server()
    print("[CyberShield] VPN Manager ready.")
