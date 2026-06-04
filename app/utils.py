import json
import re
import subprocess
from ipaddress import ip_address
from pathlib import Path


def load_json(path):
    path = Path(path)
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def save_json(path, data):
    path = Path(path)
    path.write_text(json.dumps(data, indent=2))


def is_valid_ip(value):
    if not value:
        return True
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


def normalize_mac(value):
    if not value:
        return None
    value = value.strip().lower().replace('-', ':')
    if re.fullmatch(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', value):
        return value
    compact = value.replace(':', '')
    if re.fullmatch(r'[0-9a-f]{12}', compact):
        return ':'.join(compact[i:i + 2] for i in range(0, 12, 2))
    return value


def is_valid_mac(value):
    if not value:
        return True
    return re.fullmatch(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', normalize_mac(value) or '') is not None


def find_abuse_contacts(whois_text):
    contacts = []
    for line in whois_text.splitlines():
        if 'abuse' not in line.lower():
            continue
        for email in re.findall(r'[\w.\-+%]+@[\w.\-]+\.[A-Za-z]{2,}', line):
            if email.lower() not in [item.lower() for item in contacts]:
                contacts.append(email)
    return contacts


def query_whois(host):
    try:
        out = subprocess.check_output(['whois', host], universal_newlines=True, timeout=10)
        return {
            'target': host,
            'raw': out,
            'abuse_contacts': find_abuse_contacts(out),
        }
    except Exception as e:
        return {
            'target': host,
            'raw': str(e),
            'abuse_contacts': [],
        }
