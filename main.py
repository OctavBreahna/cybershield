from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import os
from dotenv import load_dotenv
from datetime import datetime
from database import get_db_connection, get_all_clients, add_client
from report import generate_report
from scanner import scan

load_dotenv()

app = FastAPI(title="CyberShield API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("API_KEY", "cybershield-secret-2026")

def verify_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

class ClientCreate(BaseModel):
    name: str
    domain: str
    email: str
    plan: Optional[str] = "basic"

@app.get("/")
def root():
    return {"status": "ok", "service": "CyberShield API", "version": "1.0.0"}

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": str(datetime.now())}

@app.get("/clients", dependencies=[Depends(verify_key)])
def list_clients():
    clients = get_all_clients()
    return [{"id": c[0], "name": c[1], "domain": c[2], "email": c[3], "plan": c[4]} for c in clients]

@app.post("/clients", dependencies=[Depends(verify_key)])
def create_client(client: ClientCreate):
    client_id = add_client(client.name, client.domain, client.email, client.plan)
    return {"id": client_id, "message": f"Client {client.name} added successfully"}

@app.get("/clients/{client_id}/scan", dependencies=[Depends(verify_key)])
def run_scan(client_id: int):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT name, domain, email FROM clients WHERE id = %s", (client_id,))
    client = cur.fetchone()
    cur.close(); conn.close()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    name, domain, email = client
    result = scan(domain)
    return {"message": f"Scan complete for {domain}", "score": result.get("score"), "domain": domain}

@app.get("/clients/{client_id}/report", dependencies=[Depends(verify_key)])
def get_report(client_id: int):
    pdf_path = generate_report(client_id=client_id)
    if not pdf_path:
        raise HTTPException(status_code=404, detail="Could not generate report")
    return {"message": "Report generated", "path": pdf_path}

@app.get("/clients/{client_id}/scans", dependencies=[Depends(verify_key)])
def get_scans(client_id: int):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT score, scanned_at FROM scans
        WHERE client_id = %s
        ORDER BY scanned_at DESC
        LIMIT 10
    """, (client_id,))
    scans = cur.fetchall()
    cur.close(); conn.close()
    return [{"score": s[0], "scanned_at": str(s[1])} for s in scans]

from vpn_manager import add_peer, remove_peer, list_peers

class PeerCreate(BaseModel):
    peer_name: str

@app.get("/clients/{client_id}/vpn", dependencies=[Depends(verify_key)])
def get_vpn_peers(client_id: int):
    peers = list_peers(client_id)
    return {"client_id": client_id, "peers": peers}

@app.post("/clients/{client_id}/vpn", dependencies=[Depends(verify_key)])
def create_vpn_peer(client_id: int, peer: PeerCreate):
    result = add_peer(client_id, peer.peer_name)
    return {"message": f"Peer {peer.peer_name} created", "details": result}

@app.delete("/clients/{client_id}/vpn/{peer_name}", dependencies=[Depends(verify_key)])
def delete_vpn_peer(client_id: int, peer_name: str):
    success = remove_peer(client_id, peer_name)
    if not success:
        raise HTTPException(status_code=404, detail="Peer not found")
    return {"message": f"Peer {peer_name} removed"}

class ContactForm(BaseModel):
    name: str
    email: str
    domain: str
    plan: str

@app.post("/contact")
async def contact(form: ContactForm):
    import sendgrid
    from sendgrid.helpers.mail import Mail
    sg = sendgrid.SendGridAPIClient(api_key=os.getenv('SENDGRID_API_KEY'))
    message = Mail(
        from_email=os.getenv('FROM_EMAIL', 'alerts@cybersh.tech'),
        to_emails='team.cybersh@gmail.com',
        subject=f'New CyberShield Client: {form.name}',
        html_content=f'''
        <h2>New client inquiry</h2>
        <p><b>Name:</b> {form.name}</p>
        <p><b>Email:</b> {form.email}</p>
        <p><b>Domain:</b> {form.domain}</p>
        <p><b>Plan:</b> {form.plan}</p>
        '''
    )
    sg.send(message)
    return {"status": "ok"}
