import os
import threading
import time
from collections import defaultdict, deque


DEFAULT_CONFIG = {
    "port_scan_threshold": 15,
    "port_scan_window": 60,
    "icmp_flood_threshold": 20,
    "icmp_flood_window": 30,
    "syn_flood_threshold": 50,
    "syn_flood_window": 10,
    "brute_force_threshold": 20,
    "brute_force_window": 60,
    "sensitive_ports": "22,23,3389,445,5900,21,25,110,143,3306,5432",
    "cooldown": 300,
    "max_state": 5000,
}


def _load_config():
    cfg = DEFAULT_CONFIG.copy()
    for key, default in DEFAULT_CONFIG.items():
        env_key = f"HEUR_{key.upper()}"
        raw = os.getenv(env_key)
        if raw is None:
            continue
        if isinstance(default, int):
            try:
                cfg[key] = int(raw)
            except ValueError:
                pass
        else:
            cfg[key] = raw
    cfg["sensitive_ports"] = {
        int(p.strip()) for p in str(cfg["sensitive_ports"]).split(",") if p.strip().isdigit()
    }
    return cfg


class HeuristicEngine:
    """Detecta patrones sospechosos por IP de origen.

    Mantiene una ventana deslizante de eventos por src_ip y genera
    alertas cuando se superan umbrales. Tiene cooldown para no
    spamear la misma firma repetidamente.
    """

    def __init__(self, config=None):
        self.config = config or _load_config()
        self._events = defaultdict(list)
        self._cooldowns = deque()
        self._lock = threading.Lock()
        self._known_signatures = set()

    def _prune(self, src, now, window):
        cutoff = now - window
        evs = self._events[src]
        i = 0
        while i < len(evs) and evs[i][0] < cutoff:
            i += 1
        if i:
            del evs[:i]
        if len(evs) > self.config["max_state"]:
            del evs[: -self.config["max_state"]]

    def _prune_cooldowns(self, now):
        cutoff = now - self.config["cooldown"]
        while self._cooldowns and self._cooldowns[0][0] < cutoff:
            self._cooldowns.popleft()

    def _fire(self, sig, now):
        self._prune_cooldowns(now)
        for _, s in self._cooldowns:
            if s == sig:
                return False
        self._cooldowns.append((now, sig))
        return True

    def _events_in_window(self, src, window, predicate=None):
        events = self._events[src]
        if not events:
            return []
        now_max = events[-1][0]
        cutoff = now_max - window
        out = []
        for ts, ev in events:
            if ts < cutoff:
                continue
            if predicate and not predicate(ev):
                continue
            out.append(ev)
        return out

    def analyze(self, event):
        src = event.get("src_ip")
        if not src:
            return []
        ts = event.get("timestamp") or int(time.time())
        max_window = max(
            self.config["port_scan_window"],
            self.config["icmp_flood_window"],
            self.config["syn_flood_window"],
            self.config["brute_force_window"],
        )
        alerts = []
        with self._lock:
            self._events[src].append((ts, event))
            self._prune(src, ts, max_window)
            alerts.extend(self._check_port_scan(event, src, ts))
            alerts.extend(self._check_icmp_flood(event, src, ts))
            alerts.extend(self._check_syn_flood(event, src, ts))
            alerts.extend(self._check_brute_force(event, src, ts))
        return alerts

    def _check_port_scan(self, event, src, ts):
        proto = event.get("protocol")
        if proto not in ("TCP", "HTTP"):
            return []
        cfg = self.config
        evs = self._events_in_window(src, cfg["port_scan_window"], lambda e: e.get("protocol") in ("TCP", "HTTP"))
        ports = {e.get("dst_port") for e in evs if e.get("dst_port")}
        if len(ports) < cfg["port_scan_threshold"]:
            return []
        sig = f"port_scan:{src}"
        if not self._fire(sig, ts):
            return []
        return [{
            "timestamp": ts,
            "type": "heuristic",
            "subtype": "port_scan",
            "src_ip": src,
            "src_mac": event.get("src_mac"),
            "dst": event.get("dst"),
            "dst_port": event.get("dst_port"),
            "protocol": proto,
            "risk": f"Posible escaneo de puertos ({len(ports)} destinos en {cfg['port_scan_window']}s)",
            "evidence": {
                "unique_ports": len(ports),
                "sample_ports": sorted(ports)[:25],
                "window_seconds": cfg["port_scan_window"],
            },
        }]

    def _check_icmp_flood(self, event, src, ts):
        if event.get("protocol") != "ICMP":
            return []
        cfg = self.config
        evs = self._events_in_window(src, cfg["icmp_flood_window"], lambda e: e.get("protocol") == "ICMP")
        if len(evs) < cfg["icmp_flood_threshold"]:
            return []
        sig = f"icmp_flood:{src}"
        if not self._fire(sig, ts):
            return []
        return [{
            "timestamp": ts,
            "type": "heuristic",
            "subtype": "icmp_flood",
            "src_ip": src,
            "src_mac": event.get("src_mac"),
            "dst": event.get("dst"),
            "protocol": "ICMP",
            "risk": f"Posible inundacion ICMP ({len(evs)} paquetes en {cfg['icmp_flood_window']}s)",
            "evidence": {
                "icmp_packets": len(evs),
                "window_seconds": cfg["icmp_flood_window"],
            },
        }]

    def _check_syn_flood(self, event, src, ts):
        if event.get("protocol") not in ("TCP", "HTTP"):
            return []
        if not (event.get("tcp_flags") and "S" in event["tcp_flags"] and "A" not in event["tcp_flags"]):
            return []
        cfg = self.config
        evs = self._events_in_window(
            src,
            cfg["syn_flood_window"],
            lambda e: e.get("tcp_flags") and "S" in e["tcp_flags"] and "A" not in e["tcp_flags"],
        )
        if len(evs) < cfg["syn_flood_threshold"]:
            return []
        sig = f"syn_flood:{src}"
        if not self._fire(sig, ts):
            return []
        return [{
            "timestamp": ts,
            "type": "heuristic",
            "subtype": "syn_flood",
            "src_ip": src,
            "src_mac": event.get("src_mac"),
            "dst": event.get("dst"),
            "protocol": "TCP",
            "risk": f"Posible SYN flood ({len(evs)} SYNs en {cfg['syn_flood_window']}s)",
            "evidence": {
                "syn_packets": len(evs),
                "window_seconds": cfg["syn_flood_window"],
            },
        }]

    def _check_brute_force(self, event, src, ts):
        proto = event.get("protocol")
        if proto not in ("TCP", "HTTP"):
            return []
        sensitive = self.config["sensitive_ports"]
        if event.get("dst_port") not in sensitive:
            return []
        cfg = self.config
        evs = self._events_in_window(
            src,
            cfg["brute_force_window"],
            lambda e: e.get("dst_port") in sensitive,
        )
        if len(evs) < cfg["brute_force_threshold"]:
            return []
        sig = f"brute_force:{src}:{event.get('dst_port')}"
        if not self._fire(sig, ts):
            return []
        targeted = sorted({e.get("dst_port") for e in evs if e.get("dst_port") in sensitive})
        return [{
            "timestamp": ts,
            "type": "heuristic",
            "subtype": "brute_force",
            "src_ip": src,
            "src_mac": event.get("src_mac"),
            "dst": event.get("dst"),
            "dst_port": event.get("dst_port"),
            "protocol": "TCP",
            "risk": f"Posible fuerza bruta hacia puertos sensibles ({len(evs)} intentos en {cfg['brute_force_window']}s)",
            "evidence": {
                "attempts": len(evs),
                "target_ports": targeted,
                "window_seconds": cfg["brute_force_window"],
            },
        }]


_engine = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = HeuristicEngine()
    return _engine
