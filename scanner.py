import nmap
import requests
import ssl
import socket
import json
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

def scan_ports(domain):
    nm = nmap.PortScanner()
    nm.scan(domain, '21,22,23,25,80,443,3306,5432,8080,8443')
    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                state = nm[host][proto][port]['state']
                results.append({'port': port, 'state': state})
    return results

def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(5)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_left = (expire_date - datetime.utcnow()).days
        return {'valid': True, 'days_left': days_left, 'expires': str(expire_date)}
    except Exception as e:
        return {'valid': False, 'error': str(e)}

def check_blacklist(domain):
    api_key = os.getenv('GOOGLE_SAFE_BROWSING_KEY')
    if not api_key or api_key == 'your_google_key_here':
        return {'blacklisted': False, 'note': 'API key not configured'}
    url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'
    payload = {
        'client': {'clientId': 'cybersh', 'clientVersion': '1.0'},
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': f'http://{domain}'}]
        }
    }
    try:
        r = requests.post(url, json=payload, timeout=5)
        data = r.json()
        return {'blacklisted': bool(data.get('matches'))}
    except Exception as e:
        return {'blacklisted': False, 'error': str(e)}

def calculate_score(ports, ssl_info, blacklist):
    score = 100
    dangerous_ports = [21, 23, 3306, 5432]
    for p in ports:
        if p['port'] in dangerous_ports and p['state'] == 'open':
            score -= 20
    if not ssl_info.get('valid'):
        score -= 30
    elif ssl_info.get('days_left', 999) < 30:
        score -= 15
    if blacklist.get('blacklisted'):
        score -= 50
    return max(0, score)

def scan(domain):
    print(f'\n[CyberShield] Scanning {domain}...')
    ports = scan_ports(domain)
    ssl_info = check_ssl(domain)
    blacklist = check_blacklist(domain)
    score = calculate_score(ports, ssl_info, blacklist)
    result = {
        'domain': domain,
        'timestamp': str(datetime.utcnow()),
        'score': score,
        'ports': ports,
        'ssl': ssl_info,
        'blacklist': blacklist
    }
    print(json.dumps(result, indent=2))
    return result

if __name__ == '__main__':
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else 'google.com'
    scan(domain)
