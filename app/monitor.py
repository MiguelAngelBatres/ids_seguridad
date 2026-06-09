import ipaddress
import os
import threading
import time
import urllib.request
import urllib.error
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

_DATA_LOCK = threading.Lock()
_MAX_EVENTS = 10000

def _rebuild_blacklist_sets(blacklist):
    ips = set()
    domains = set()
    for entry in blacklist:
        if entry.get('ip'):
            ips.add(entry['ip'].lower())
        if entry.get('host'):
            domains.add(entry['host'].lower())
        if entry.get('domain'):
            domains.add(entry['domain'].lower())
    return ips, domains

_initial_blacklist = load_json(BLACKLIST_FILE)
_initial_ips, _initial_domains = _rebuild_blacklist_sets(_initial_blacklist)

_STATE = {
    'whitelist': load_json(WHITELIST_FILE),
    'reports': load_json(REPORTS_FILE),
    'alerts': load_json(ALERTS_FILE),
    'blacklist': _initial_blacklist,
    'blacklist_ips': _initial_ips,
    'blacklist_domains': _initial_domains,
}
_NEEDS_FLUSH = False


def _disk_flusher():
    global _NEEDS_FLUSH
    while True:
        time.sleep(3.0)
        with _DATA_LOCK:
            if not _NEEDS_FLUSH:
                continue
            whitelist = list(_STATE['whitelist'])
            reports = list(_STATE['reports'])
            alerts = list(_STATE['alerts'])
            _NEEDS_FLUSH = False
        
        try:
            save_json(WHITELIST_FILE, whitelist)
            save_json(REPORTS_FILE, reports)
            save_json(ALERTS_FILE, alerts)
        except Exception as e:
            print(f'Error flushing disk: {e}')


threading.Thread(target=_disk_flusher, daemon=True).start()


def _update_external_blacklist():
    while True:
        try:
            print("Descargando listas negras de inteligencia de amenazas...")
            new_entries = []
            
            # 1. Feodo Tracker (Botnet C2)
            try:
                req = urllib.request.Request(
                    'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', 
                    headers={'User-Agent': 'Mozilla/5.0 (IDS Console)'}
                )
                with urllib.request.urlopen(req, timeout=15) as r:
                    for line in r.read().decode('utf-8').splitlines():
                        line = line.strip()
                        if line and not line.startswith('#'):
                            new_entries.append({
                                'ip': line,
                                'risk': 'Botnet C2',
                                'note': 'Abuse.ch Feodo Tracker'
                            })
            except Exception as e:
                print(f"Error descargando Feodo Tracker: {e}")

            # 2. CINS Army
            try:
                req = urllib.request.Request(
                    'http://cinsscore.com/list/ci-badguys.txt',
                    headers={'User-Agent': 'Mozilla/5.0 (IDS Console)'}
                )
                with urllib.request.urlopen(req, timeout=15) as r:
                    for line in r.read().decode('utf-8').splitlines():
                        line = line.strip()
                        if line and not line.startswith('#'):
                            new_entries.append({
                                'ip': line,
                                'risk': 'Malware/Scanner',
                                'note': 'CINS Army'
                            })
            except Exception as e:
                print(f"Error descargando CINS Army: {e}")

            if new_entries:
                ips, domains = _rebuild_blacklist_sets(new_entries)
                with _DATA_LOCK:
                    _STATE['blacklist'] = new_entries
                    _STATE['blacklist_ips'] = ips
                    _STATE['blacklist_domains'] = domains
                try:
                    save_json(BLACKLIST_FILE, new_entries)
                except Exception as e:
                    print(f"Error guardando blacklist: {e}")
                print(f"Lista negra actualizada: {len(new_entries)} entradas.")

        except Exception as e:
            print(f"Error general en la actualizacion de la lista negra: {e}")
            
        time.sleep(86400) # 24 horas

threading.Thread(target=_update_external_blacklist, daemon=True).start()


def get_whitelist():
    with _DATA_LOCK:
        return list(_STATE['whitelist'])


def add_whitelist_entry(ip, mac, note=None):
    global _NEEDS_FLUSH
    ip = (ip or '').strip() or None
    mac = normalize_mac(mac)
    note = (note or '').strip() or None

    if not ip and not mac:
        raise ValueError('Debes capturar al menos una IP o una MAC')
    if not is_valid_ip(ip):
        raise ValueError('La IP no tiene un formato valido')
    if not is_valid_mac(mac):
        raise ValueError('La MAC no tiene un formato valido')

    with _DATA_LOCK:
        for entry in _STATE['whitelist']:
            if ip and ip == entry.get('ip'):
                raise ValueError('La IP ya existe en la lista blanca')
            if mac and mac == normalize_mac(entry.get('mac')):
                raise ValueError('La MAC ya existe en la lista blanca')

        key = f"{ip or ''}-{mac or ''}-{int(time.time())}"
        _STATE['whitelist'].append({'key': key, 'ip': ip, 'mac': mac, 'note': note})
        _NEEDS_FLUSH = True
    return key


def add_blacklist_entry(ip=None, host=None, domain=None, risk=None, note=None):
    global _NEEDS_FLUSH
    ip = (ip or '').strip() or None
    host = (host or '').strip() or None
    domain = (domain or '').strip() or None
    risk = (risk or '').strip() or None
    note = (note or '').strip() or None

    if not ip and not host and not domain:
        raise ValueError('Debes capturar al menos una IP, host o dominio')

    with _DATA_LOCK:
        key = f"{ip or ''}-{host or ''}-{domain or ''}-{int(time.time())}"
        _STATE['blacklist'].append({
            'key': key, 'ip': ip, 'host': host,
            'domain': domain, 'risk': risk, 'note': note,
        })
        ips, domains = _rebuild_blacklist_sets(_STATE['blacklist'])
        _STATE['blacklist_ips'] = ips
        _STATE['blacklist_domains'] = domains
        _NEEDS_FLUSH = True
    return key


def remove_whitelist_entry(key):
    global _NEEDS_FLUSH
    with _DATA_LOCK:
        _STATE['whitelist'] = [e for e in _STATE['whitelist'] if e.get('key') != key]
        _NEEDS_FLUSH = True


def remove_blacklist_entry(key):
    global _NEEDS_FLUSH
    with _DATA_LOCK:
        _STATE['blacklist'] = [e for e in _STATE['blacklist'] if e.get('key') != key]
        ips, domains = _rebuild_blacklist_sets(_STATE['blacklist'])
        _STATE['blacklist_ips'] = ips
        _STATE['blacklist_domains'] = domains
        _NEEDS_FLUSH = True


def get_reports():
    with _DATA_LOCK:
        return list(_STATE['reports'])


def get_alerts():
    with _DATA_LOCK:
        return list(_STATE['alerts'])


def get_alerts_since(since_ts):
    with _DATA_LOCK:
        return [a for a in _STATE['alerts'] if int(a.get('timestamp', 0) or 0) > since_ts]


def get_reports_since(since_ts):
    with _DATA_LOCK:
        return [r for r in _STATE['reports'] if int(r.get('timestamp', 0) or 0) > since_ts]


def clear_alerts():
    global _NEEDS_FLUSH
    with _DATA_LOCK:
        _STATE['alerts'] = []
        _NEEDS_FLUSH = True


def _clear_file(filepath):
    with _reports_lock:
        save_json(filepath, [])


def clear_reports():
    global _NEEDS_FLUSH
    with _DATA_LOCK:
        _STATE['reports'] = []
        _NEEDS_FLUSH = True


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


def _find_threat(event):
    dst = (event.get('dst') or '').lower()
    domain = (event.get('domain') or '').lower()
    
    with _DATA_LOCK:
        if dst in _STATE['blacklist_ips'] or domain in _STATE['blacklist_domains']:
            candidates = {v for v in (dst, domain) if v}
            for entry in _STATE['blacklist']:
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
    global _NEEDS_FLUSH
    with _DATA_LOCK:
        _STATE['alerts'].append(alert)
        if len(_STATE['alerts']) > _MAX_EVENTS:
            _STATE['alerts'] = _STATE['alerts'][-_MAX_EVENTS:]
        _NEEDS_FLUSH = True


def _send_email_async(alert, with_whois=False):
    def _runner():
        whois_result = None
        if with_whois:
            target = alert.get('dst') or alert.get('domain')
            whois_result = query_whois(target) if target else None
            if whois_result:
                with _DATA_LOCK:
                    if 'evidence' not in alert:
                        alert['evidence'] = {}
                    if whois_result.get('abuse_contacts'):
                        alert['evidence']['abuse_contacts'] = whois_result['abuse_contacts']
                    if whois_result.get('raw'):
                        lines = whois_result['raw'].splitlines()
                        alert['evidence']['whois_raw'] = lines[:30] # Limitamos a 30 lineas para no saturar la UI
                    global _NEEDS_FLUSH
                    _NEEDS_FLUSH = True
        try:
            send_alert_email(alert, whois_result)
        except Exception as e:
            print('Error enviando alerta:', e)
    threading.Thread(target=_runner, daemon=True).start()


def _emit_alert(alert, with_whois=False):
    _persist_alert(alert)
    _send_email_async(alert, with_whois=with_whois)


def _handle_event(event):
    global _NEEDS_FLUSH
    event.setdefault('timestamp', int(time.time()))
    event['src_mac'] = normalize_mac(event.get('src_mac'))
    event['dst_mac'] = normalize_mac(event.get('dst_mac'))

    with _DATA_LOCK:
        _STATE['reports'].append(event)
        if len(_STATE['reports']) > _MAX_EVENTS:
            _STATE['reports'] = _STATE['reports'][-_MAX_EVENTS:]
        _NEEDS_FLUSH = True

    whitelist = get_whitelist()
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
            'evidence': {
                'motivo': 'IP/MAC no encontrada en whitelist.json',
                'src_ip': event.get('src_ip'),
                'src_mac': event.get('src_mac'),
                'dst': event.get('dst'),
                'dst_port': event.get('dst_port'),
                'protocolo': event.get('protocol'),
                'tamaño_paquete': event.get('size'),
            },
        }
        _emit_alert(alert)

        for alert in get_engine().analyze(event):
            _emit_alert(alert)

    threat = _find_threat(event)
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
            'evidence': {
                'motivo': 'Conexión a IP/dominio en lista negra',
                'blacklist_ip': threat.get('ip'),
                'blacklist_host': threat.get('host'),
                'blacklist_domain': threat.get('domain'),
                'riesgo': threat.get('risk'),
                'nota': threat.get('note'),
                'src_ip': event.get('src_ip'),
                'src_mac': event.get('src_mac'),
                'dst_port': event.get('dst_port'),
                'protocolo': event.get('protocol'),
            },
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
            'evidence': {
                'motivo': 'MAC observada no coincide con la registrada en whitelist',
                'ip': event.get('src_ip'),
                'mac_esperada': arp['expected_mac'],
                'mac_observada': arp['actual_mac'],
                'dst': event.get('dst'),
                'protocolo': event.get('protocol'),
            },
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
