import ipaddress
import os
import threading
import time
from pathlib import Path

from .emailer import send_alert_email
from .heuristics import get_engine
from .utils import (
    is_valid_ip,
    is_valid_mac,
    load_json,
    normalize_mac,
    query_whois,
    save_json,
)

_LIVE_HOST = '8.8.8.8'
_LIVE_PORT = 80

_DEFAULT_LOCAL_NETS = '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'


def _load_local_nets():
    raw = os.getenv('IDS_LOCAL_NETS', _DEFAULT_LOCAL_NETS)
    nets = []
    for chunk in raw.split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            nets.append(ipaddress.ip_network(chunk, strict=False))
        except ValueError:
            print(f'IDS_LOCAL_NETS: red invalida ignorada: {chunk!r}')
    return nets


_LOCAL_NETS = _load_local_nets()


def _is_local(ip):
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _LOCAL_NETS)

DATA_DIR = Path(__file__).resolve().parents[1] / 'data'
DATA_DIR.mkdir(parents=True, exist_ok=True)

WHITELIST_FILE = DATA_DIR / 'whitelist.json'
BLACKLIST_FILE = DATA_DIR / 'blacklist.json'
REPORTS_FILE = DATA_DIR / 'reports.json'
ALERTS_FILE = DATA_DIR / 'alerts.json'

for f in (WHITELIST_FILE, BLACKLIST_FILE, REPORTS_FILE, ALERTS_FILE):
    if not f.exists():
        f.write_text('[]', encoding='utf-8')


_monitor_thread = None
_monitor_lock = threading.Lock()


def get_whitelist():
    return load_json(WHITELIST_FILE)


def add_whitelist_entry(ip, mac, note=None):
    ip = (ip or '').strip() or None
    mac = normalize_mac(mac)
    note = (note or '').strip() or None

    if not ip and not mac:
        raise ValueError('Debes capturar al menos una IP o una MAC')
    if not is_valid_ip(ip):
        raise ValueError('La IP no tiene un formato valido')
    if not is_valid_mac(mac):
        raise ValueError('La MAC no tiene un formato valido')

    entries = get_whitelist()
    for entry in entries:
        if ip and ip == entry.get('ip'):
            raise ValueError('La IP ya existe en la lista blanca')
        if mac and mac == normalize_mac(entry.get('mac')):
            raise ValueError('La MAC ya existe en la lista blanca')

    key = f"{ip or ''}-{mac or ''}-{int(time.time())}"
    entries.append({'key': key, 'ip': ip, 'mac': mac, 'note': note})
    save_json(WHITELIST_FILE, entries)
    return key


def remove_whitelist_entry(key):
    entries = get_whitelist()
    entries = [e for e in entries if e.get('key') != key]
    save_json(WHITELIST_FILE, entries)


def get_reports():
    return load_json(REPORTS_FILE)


def get_alerts():
    return load_json(ALERTS_FILE)


def get_alerts_since(since_ts):
    return [a for a in get_alerts() if int(a.get('timestamp', 0) or 0) > since_ts]


def get_reports_since(since_ts):
    return [r for r in get_reports() if int(r.get('timestamp', 0) or 0) > since_ts]


def clear_alerts():
    save_json(ALERTS_FILE, [])


def clear_reports():
    save_json(REPORTS_FILE, [])


def _source_whitelisted(event, whitelist):
    src_mac = normalize_mac(event.get('src_mac'))
    src_ip = event.get('src_ip')
    for entry in whitelist:
        entry_ip = entry.get('ip')
        entry_mac = normalize_mac(entry.get('mac'))
        if src_ip and entry_ip and src_ip == entry_ip:
            return True
        if src_mac and entry_mac and src_mac == entry_mac:
            return True
    return False


def _find_threat(event, blacklist):
    candidates = {
        v.lower() for v in (event.get('dst'), event.get('domain')) if v
    }
    for entry in blacklist:
        values = {
            v.lower() for v in (entry.get('ip'), entry.get('host'), entry.get('domain')) if v
        }
        if candidates & values:
            return entry
    return None


def _detect_arp_spoof(event, whitelist):
    src_ip = event.get('src_ip')
    src_mac = normalize_mac(event.get('src_mac'))
    if not src_ip or not src_mac:
        return None
    for entry in whitelist:
        entry_ip = entry.get('ip')
        entry_mac = normalize_mac(entry.get('mac'))
        if entry_ip and src_ip == entry_ip and entry_mac and src_mac != entry_mac:
            return {
                'expected_mac': entry_mac,
                'actual_mac': src_mac,
            }
    return None


def _persist_alert(alert):
    alerts = load_json(ALERTS_FILE)
    alerts.append(alert)
    save_json(ALERTS_FILE, alerts)


def _send_email_async(alert, with_whois=False):
    def _runner():
        whois_result = None
        if with_whois:
            target = alert.get('dst') or alert.get('domain')
            whois_result = query_whois(target) if target else None
        try:
            send_alert_email(alert, whois_result)
        except Exception as e:
            print('Error enviando alerta:', e)
    threading.Thread(target=_runner, daemon=True).start()


def _emit_alert(alert, with_whois=False):
    _persist_alert(alert)
    _send_email_async(alert, with_whois=with_whois)


def _handle_event(event):
    event.setdefault('timestamp', int(time.time()))
    event['src_mac'] = normalize_mac(event.get('src_mac'))
    event['dst_mac'] = normalize_mac(event.get('dst_mac'))

    reports = load_json(REPORTS_FILE)
    reports.append(event)
    save_json(REPORTS_FILE, reports)

    whitelist = get_whitelist()
    blacklist = load_json(BLACKLIST_FILE)
    src_trusted = _source_whitelisted(event, whitelist)

    if not src_trusted and _is_local(event.get('src_ip')):
        alert = {
            'timestamp': event.get('timestamp', int(time.time())),
            'type': 'unauthorized_device',
            'src_ip': event.get('src_ip'),
            'src_mac': event.get('src_mac'),
            'src_port': event.get('src_port'),
            'dst': event.get('dst'),
            'dst_port': event.get('dst_port'),
            'domain': event.get('domain'),
            'protocol': event.get('protocol'),
            'risk': 'Equipo no registrado en lista blanca',
        }
        _emit_alert(alert)

        for alert in get_engine().analyze(event):
            _emit_alert(alert)

    threat = _find_threat(event, blacklist)
    if threat:
        alert = {
            'timestamp': event.get('timestamp', int(time.time())),
            'type': 'threat_intel',
            'src_ip': event.get('src_ip'),
            'src_mac': event.get('src_mac'),
            'src_port': event.get('src_port'),
            'dst': event.get('dst'),
            'dst_port': event.get('dst_port'),
            'domain': event.get('domain'),
            'protocol': event.get('protocol'),
            'risk': threat.get('risk', 'Riesgo desconocido'),
            'blacklist_note': threat.get('note'),
        }
        _emit_alert(alert, with_whois=True)

    arp = _detect_arp_spoof(event, whitelist)
    if arp:
        alert = {
            'timestamp': event.get('timestamp', int(time.time())),
            'type': 'arp_spoof',
            'src_ip': event.get('src_ip'),
            'src_mac': event.get('src_mac'),
            'dst': event.get('dst'),
            'protocol': event.get('protocol'),
            'risk': 'Posible ARP spoofing: la IP de la lista blanca aparece con una MAC distinta',
            'expected_mac': arp['expected_mac'],
            'actual_mac': arp['actual_mac'],
        }
        _emit_alert(alert)


def _tcp_flags(pkt):
    try:
        flags_field = pkt['TCP'].flags
        out = ''
        for bit, label in (('S', 'S'), ('A', 'A'), ('F', 'F'), ('R', 'R'), ('P', 'P'), ('U', 'U')):
            try:
                if int(flags_field) & 0x01 and label == 'F':
                    out += 'F'
                if int(flags_field) & 0x02 and label == 'S':
                    out += 'S'
                if int(flags_field) & 0x04 and label == 'R':
                    out += 'R'
                if int(flags_field) & 0x08 and label == 'P':
                    out += 'P'
                if int(flags_field) & 0x10 and label == 'A':
                    out += 'A'
            except Exception:
                pass
        return out or None
    except Exception:
        return None


def _proto_name(num):
    return {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 132: 'SCTP'}.get(num)


def _dns_name(pkt, dns_layer):
    try:
        qname = dns_layer.qd.qname
        if isinstance(qname, bytes):
            qname = qname.decode(errors='ignore')
        return qname.rstrip('.')
    except Exception:
        return None


def _http_host(raw_payload):
    try:
        text = bytes(raw_payload).decode('latin-1', errors='ignore')
    except Exception:
        return None
    if not text.startswith(('GET ', 'POST ', 'HEAD ', 'PUT ', 'DELETE ', 'OPTIONS ', 'PATCH ')):
        return None
    for line in text.splitlines():
        if line.lower().startswith('host:'):
            return line.split(':', 1)[1].strip()
    return None


def monitor_loop(stop_after=None, use_scapy=False, iface=None, bpf_filter=None):
    if use_scapy:
        try:
            from scapy.all import ARP, DNS, Ether, ICMP, IP, Raw, TCP, UDP, sniff
        except Exception as e:
            print('Scapy import failed, falling back to simulation:', e)
            use_scapy = False

    if use_scapy:
        print('Iniciando captura de paquetes con scapy...')

        def _pkt_cb(pkt):
            src_ip = None
            src_mac = None
            src_port = None
            dst = None
            dst_port = None
            dst_mac = None
            proto = None
            domain = None
            tcp_flags = None
            size = len(pkt)

            if pkt.haslayer(Ether):
                src_mac = pkt.src
                dst_mac = pkt.dst

            if pkt.haslayer(ARP):
                src_ip = pkt[ARP].psrc
                dst = pkt[ARP].pdst
                proto = 'ARP'
            elif pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst = pkt[IP].dst
                proto = _proto_name(int(pkt[IP].proto)) or str(pkt[IP].proto)
                if pkt.haslayer(TCP):
                    src_port = int(pkt[TCP].sport)
                    dst_port = int(pkt[TCP].dport)
                    tcp_flags = _tcp_flags(pkt)
                    if pkt.haslayer(Raw):
                        host = _http_host(pkt[Raw].load)
                        if host:
                            domain = host
                            proto = 'HTTP'
                elif pkt.haslayer(UDP):
                    src_port = int(pkt[UDP].sport)
                    dst_port = int(pkt[UDP].dport)
                    if pkt.haslayer(DNS) and pkt[DNS].qd:
                        proto = 'DNS'
                        domain = _dns_name(pkt, pkt[DNS])
                elif pkt.haslayer(ICMP):
                    proto = 'ICMP'

            event = {
                'timestamp': int(time.time()),
                'src_ip': src_ip,
                'src_mac': src_mac,
                'src_port': src_port,
                'dst': dst,
                'dst_port': dst_port,
                'dst_mac': dst_mac,
                'domain': domain,
                'protocol': proto,
                'tcp_flags': tcp_flags,
                'size': size,
            }
            _handle_event(event)

        capture_filter = bpf_filter or 'udp port 53 or tcp port 80 or ip or arp'
        promisc = os.getenv('SCAPY_PROMISC', '1').lower() in ('1', 'true', 'yes')
        if promisc:
            print('Captura en modo promiscuo (escucha todo el trafico del segmento)')
        try:
            sniff(prn=_pkt_cb, iface=iface, filter=capture_filter, store=False, promisc=promisc)
        except PermissionError:
            print('ERROR: No tienes permisos para capturar paquetes.')
            print('  Soluciones:')
            print('    1) sudo -E python -m app.main')
            print('    2) sudo setcap cap_net_raw+eip "$(which python3)"')
            print('    3) SCAPY_ENABLE=0 para modo simulación')
            return
        except OSError as e:
            print(f'ERROR de captura ({e.errno}): {e.strerror}')
            print(f'  Interfaz: {iface or "(auto)"} | Filtro: {capture_filter}')
            return
        except Exception as e:
            print(f'ERROR inesperado en captura scapy: {type(e).__name__}: {e}')
            return
        return

    print('Modo simulación: generando eventos de ejemplo (use SCAPY_ENABLE=1 para captura real)')
    counter = 0
    import random
    protocols = ['HTTP', 'DNS', 'ICMP', 'TCP', 'UDP']
    tcp_ports = [80, 443, 22, 3389, 8080, 3306]
    udp_ports = [123, 161, 514, 1194, 5353, 4500]
    while True:
        proto = random.choice(protocols)
        if proto in ('HTTP', 'TCP'):
            dst_port = random.choice(tcp_ports)
        elif proto == 'DNS':
            dst_port = 53
        elif proto == 'UDP':
            dst_port = random.choice(udp_ports)
        else:
            dst_port = None
        fake_event = {
            'timestamp': int(time.time()),
            'src_ip': '192.0.2.10',
            'src_mac': 'aa:bb:cc:dd:ee:ff',
            'src_port': random.randint(1024, 65535),
            'dst': '203.0.113.66',
            'dst_port': dst_port,
            'dst_mac': '00:11:22:33:44:55',
            'domain': 'malicious.example' if proto == 'HTTP' else None,
            'protocol': proto,
            'tcp_flags': 'S' if proto == 'TCP' else None,
            'size': random.randint(64, 1500),
        }
        _handle_event(fake_event)
        counter += 1
        if stop_after and counter >= stop_after:
            break
        time.sleep(2)


def start_monitoring():
    global _monitor_thread

    with _monitor_lock:
        if _monitor_thread and _monitor_thread.is_alive():
            return {'status': 'already running'}

        use_scapy = os.getenv('SCAPY_ENABLE', '0').lower() in ('1', 'true', 'yes')
        kwargs = {
            'stop_after': None,
            'use_scapy': use_scapy,
            'iface': os.getenv('SCAPY_IFACE') or None,
            'bpf_filter': os.getenv('SCAPY_BPF') or None,
        }
        _monitor_thread = threading.Thread(target=monitor_loop, kwargs=kwargs, daemon=True)
        _monitor_thread.start()
        mode = 'real' if use_scapy else 'simulacion'
        return {'status': 'started', 'mode': mode}
