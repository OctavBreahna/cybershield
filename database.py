import psycopg2
from dotenv import load_dotenv
import os
from datetime import datetime

load_dotenv()

DB_CONFIG = {
    'dbname': os.getenv('DB_NAME', 'cybersh'),
    'user': os.getenv('DB_USER', 'cybersh_user'),
    'password': os.getenv('DB_PASSWORD'),  # fara fallback - trebuie setat in .env
    'host': os.getenv('DB_HOST', 'localhost')
}

def get_connection():
    return psycopg2.connect(**DB_CONFIG)

def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            domain VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            plan VARCHAR(50) DEFAULT 'basic',
            active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT NOW()
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            client_id INTEGER REFERENCES clients(id),
            domain VARCHAR(255),
            score INTEGER,
            ports JSONB,
            ssl JSONB,
            blacklist JSONB,
            scanned_at TIMESTAMP DEFAULT NOW()
        )
    ''')
    conn.commit()
    cur.close()
    conn.close()
    print('Database initialized successfully!')

def add_client(name, domain, email, plan='basic'):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO clients (name, domain, email, plan) VALUES (%s, %s, %s, %s) RETURNING id',
        (name, domain, email, plan)
    )
    client_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    print(f'Client {name} added with ID: {client_id}')
    return client_id

def get_all_clients():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, name, domain, email, plan FROM clients WHERE active = TRUE')
    clients = cur.fetchall()
    cur.close()
    conn.close()
    return clients

def save_scan(client_id, domain, score, ports, ssl, blacklist):
    conn = get_connection()
    cur = conn.cursor()
    import json
    cur.execute(
        'INSERT INTO scans (client_id, domain, score, ports, ssl, blacklist) VALUES (%s, %s, %s, %s, %s, %s)',
        (client_id, domain, score, json.dumps(ports), json.dumps(ssl), json.dumps(blacklist))
    )
    conn.commit()
    cur.close()
    conn.close()
    print(f'Scan saved for {domain} — Score: {score}')

def get_last_scan(client_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        'SELECT score, ports, ssl, blacklist, scanned_at FROM scans WHERE client_id = %s ORDER BY scanned_at DESC LIMIT 1',
        (client_id,)
    )
    scan = cur.fetchone()
    cur.close()
    conn.close()
    return scan

if __name__ == '__main__':
    init_db()
    # Test: adaugă un client demo
    client_id = add_client('Test Restaurant', 'google.com', 'test@example.com', 'basic')
    print(f'Test client created: ID {client_id}')
    clients = get_all_clients()
    print(f'All clients: {clients}')

get_db_connection = get_connection
