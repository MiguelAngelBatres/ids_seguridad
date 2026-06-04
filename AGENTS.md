# IDS Seguridad — Agent guide

## Project
Single-package Flask IDS (`app/`). Captures/scans network events, checks whitelist/blacklist, generates alerts, optionally emails them. **No tests**, no lint/typecheck/CI setup.

## Run
```bash
python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
cp .env.example .env
python -m app.main                  # simulation mode (default)
SCAPY_ENABLE=1 sudo -E python -m app.main   # real capture (needs tcpdump, libpcap, whois)
```

## Docker
```bash
docker compose up --build           # uses network_mode: host; set SCAPY_ENABLE=0 to skip capture
```

## Key env
- `SCAPY_ENABLE`: `1` = real scapy capture, `0` = simulation (default)
- `FLASK_DEBUG=1` enables debug; `use_reloader=False` is hardcoded so monitor doesn't fork twice
- SMTP vars are optional — alerts print to stdout if unset

## Data
All persisted as JSON in `data/` (`whitelist.json`, `reports.json`, `alerts.json`, `blacklist.json`). These files are auto-created empty if missing. Only `data/*.json` survive container restarts via bind mount.

The IDS is fully passive (Wireshark-like): it never auto-modifies `whitelist.json` or any other data file. Every entry — including the local host's IP/MAC — must be added by the administrator through the web UI or by editing the JSON directly.

## Entrypoint
`app/main.py` — `start_monitoring()` launches a daemon thread that either sniffs packets with scapy or generates fake events every 10s. Web server listens on `0.0.0.0:$PORT`.

## Alert model
Four alert types are emitted to `data/alerts.json` and (if SMTP is configured) emailed to `ADMIN_EMAIL`:

- `unauthorized_device` — source IP or MAC not in `whitelist.json` (rubric: whitelist module).
- `threat_intel` — destination matches an entry in `blacklist.json` (rubric: dangerous IPs). Includes a Whois/Abuse lookup in the email body.
- `arp_spoof` — source IP is whitelisted but its observed MAC differs from the binding in `whitelist.json`.
- `heuristic` — anomaly detected by `app/heuristics.py` (port scan, ICMP flood, SYN flood, brute force on sensitive ports). Suppressed for whitelisted sources to avoid noise from local scanning.

All four send email async via `app/emailer.py`; if `SMTP_HOST`/`ADMIN_EMAIL` are unset the email step is skipped and only `alerts.json` is written.

## Heuristic engine
`app/heuristics.py` keeps a per-source sliding window in memory. Thresholds are env-tunable via `HEUR_*` (see `.env.example`). Each signature has a 5-minute cooldown to prevent repeat alerts.
