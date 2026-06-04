import base64
import json
import os
import smtplib
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from email.utils import formataddr
from dotenv import load_dotenv

load_dotenv()

GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'


def _env(key, default=None):
    val = os.getenv(key)
    if val is None or val == '':
        return default
    return val


def _env_bool(key, default=False):
    raw = _env(key)
    if raw is None:
        return default
    return raw.strip().lower() in ('1', 'true', 'yes', 'on', 'si', 'sí')


def _env_int(key, default):
    raw = _env(key)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


SMTP_HOST = _env('SMTP_HOST')
SMTP_PORT = _env_int('SMTP_PORT', 587)
SMTP_USER = _env('SMTP_USER')
SMTP_PASS = _env('SMTP_PASS')
SMTP_FROM = _env('SMTP_FROM') or SMTP_USER or 'ids@example.local'
SMTP_FROM_NAME = _env('SMTP_FROM_NAME', 'IDS Seguridad')
ADMIN_EMAIL = _env('ADMIN_EMAIL')

# --- OAuth2 (XOAUTH2 contra Gmail) ---
# Si EMAIL_USER + CLIENT_ID + CLIENT_SECRET + OAUTH_REFRESH_TOKEN están
# definidos, el envío usa XOAUTH2 en lugar de SMTP_USER/SMTP_PASS.
EMAIL_USER = _env('EMAIL_USER')
CLIENT_ID = _env('CLIENT_ID')
CLIENT_SECRET = _env('CLIENT_SECRET')
OAUTH_REFRESH_TOKEN = _env('OAUTH_REFRESH_TOKEN')
OAUTH_TOKEN_URI = _env('OAUTH_TOKEN_URI', GOOGLE_TOKEN_URL)
OAUTH_REDIRECT_URI = _env('OAUTH_REDIRECT_URI') or _env('REDIRECT_URI')

OAUTH_ENABLED = bool(EMAIL_USER and CLIENT_ID and CLIENT_SECRET and OAUTH_REFRESH_TOKEN)

_use_ssl_env = _env('SMTP_USE_SSL')
if _use_ssl_env is None:
    SMTP_USE_SSL = SMTP_PORT == 465
else:
    SMTP_USE_SSL = _use_ssl_env.strip().lower() in ('1', 'true', 'yes', 'on', 'si', 'sí')

_use_tls_env = _env('SMTP_USE_TLS')
if _use_tls_env is None:
    SMTP_USE_TLS = not SMTP_USE_SSL
else:
    SMTP_USE_TLS = _use_tls_env.strip().lower() in ('1', 'true', 'yes', 'on', 'si', 'sí')

EMAIL_COOLDOWN = _env_int('EMAIL_COOLDOWN', 300)

_dedupe_lock = threading.Lock()
_sent_signatures = {}


def _alert_signature(alert):
    t = alert.get('type', 'alerta')
    if t == 'unauthorized_device':
        return (t, alert.get('src_ip'), alert.get('src_mac'))
    if t == 'threat_intel':
        return (t, alert.get('src_ip'), alert.get('dst') or alert.get('domain'))
    if t == 'arp_spoof':
        return (t, alert.get('src_ip'), alert.get('actual_mac') or alert.get('src_mac'))
    if t == 'heuristic':
        return (
            t,
            alert.get('subtype'),
            alert.get('src_ip'),
            alert.get('dst_port'),
        )
    return (
        t,
        alert.get('src_ip'),
        alert.get('dst') or alert.get('domain'),
        alert.get('subtype'),
    )


def _should_send(signature, now=None):
    if EMAIL_COOLDOWN <= 0:
        return True
    now = now or time.time()
    with _dedupe_lock:
        cutoff = now - EMAIL_COOLDOWN
        for sig, ts in list(_sent_signatures.items()):
            if ts < cutoff:
                del _sent_signatures[sig]
        last = _sent_signatures.get(signature)
        if last is not None and last >= cutoff:
            return False
        _sent_signatures[signature] = now
        return True


def reset_dedupe_cache():
    with _dedupe_lock:
        _sent_signatures.clear()


def _exchange_refresh_token():
    """Intercambia el refresh_token de Google por un access_token."""
    payload_body = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'refresh_token': OAUTH_REFRESH_TOKEN,
        'grant_type': 'refresh_token',
    }
    # Google exige redirect_uri en el refresh para clientes web, debe
    # coincidir con el usado al obtener el refresh_token.
    if OAUTH_REDIRECT_URI:
        payload_body['redirect_uri'] = OAUTH_REDIRECT_URI

    data = urllib.parse.urlencode(payload_body).encode()
    req = urllib.request.Request(
        OAUTH_TOKEN_URI,
        data=data,
        method='POST',
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = ''
        try:
            body = e.read().decode(errors='replace')
        except Exception:
            pass
        raise RuntimeError(f'Google token endpoint HTTP {e.code}: {body or e.reason}') from e
    token = payload.get('access_token')
    if not token:
        raise RuntimeError(f'Google no devolvió access_token: {payload}')
    return token


def _xoauth2_login(smtp, username, access_token):
    """Autentica contra SMTP usando el mecanismo XOAUTH2."""
    raw = f"user={username}\x01auth=Bearer {access_token}\x01\x01".encode()
    auth_b64 = base64.b64encode(raw).decode()
    code, resp = smtp.docmd('AUTH', 'XOAUTH2 ' + auth_b64)
    if code != 235:
        raise smtplib.SMTPAuthenticationError(code, resp)


def send_email(subject, body, to_email=None):
    recipient = to_email or ADMIN_EMAIL
    if not recipient:
        print('No ADMIN_EMAIL configurado, omitiendo envío de correo')
        return False

    use_oauth = OAUTH_ENABLED
    host = SMTP_HOST or ('smtp.gmail.com' if use_oauth else None)
    if not host:
        print('No SMTP_HOST configurado, omitiendo envío de correo')
        return False

    # XOAUTH2 exige TLS: forzamos STARTTLS (o SSL) si el usuario no lo configuró.
    if use_oauth:
        port = SMTP_PORT if SMTP_PORT else 587
        use_ssl = SMTP_PORT == 465
        use_tls = not use_ssl
    else:
        port = SMTP_PORT
        use_ssl = SMTP_USE_SSL
        use_tls = SMTP_USE_TLS

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = formataddr((SMTP_FROM_NAME, SMTP_FROM))
    msg['To'] = recipient
    msg.set_content(body)

    try:
        if use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, timeout=15, context=context) as s:
                s.ehlo()
                if use_oauth:
                    token = _exchange_refresh_token()
                    _xoauth2_login(s, EMAIL_USER, token)
                elif SMTP_USER and SMTP_PASS:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as s:
                s.ehlo()
                if use_tls:
                    s.starttls(context=ssl.create_default_context())
                    s.ehlo()
                if use_oauth:
                    token = _exchange_refresh_token()
                    _xoauth2_login(s, EMAIL_USER, token)
                elif SMTP_USER and SMTP_PASS:
                    s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
        print(f'Email enviado a {recipient} via {"XOAUTH2" if use_oauth else "SMTP"}: {subject}')
        return True
    except Exception as e:
        print(f'Error enviando email ({host}:{port} ssl={use_ssl} tls={use_tls} oauth={use_oauth}):', e)
        return False


def _alert_subject(alert):
    t = alert.get('type', 'alerta')
    subtype = alert.get('subtype')
    label = f"{t}:{subtype}" if subtype else t
    prefix_map = {
        'threat_intel': 'Amenaza',
        'heuristic': 'Heuristica',
        'arp_spoof': 'ARP Spoof',
        'unauthorized_device': 'Equipo no autorizado',
    }
    prefix = prefix_map.get(t, 'Alerta')
    return f"[IDS] {prefix} {label}: {alert.get('src_ip')} -> {alert.get('dst') or alert.get('domain')}"


def format_alert_body(alert, whois_result=None):
    lines = [
        'Alerta detectada por IDS Seguridad',
        '',
        f"Tipo: {alert.get('type', 'Alerta')}",
    ]
    if alert.get('subtype'):
        lines.append(f"Subtipo: {alert.get('subtype')}")
    lines.extend([
        f"Riesgo: {alert.get('risk', 'Desconocido')}",
        f"Origen IP: {alert.get('src_ip') or 'N/D'}",
        f"Origen MAC: {alert.get('src_mac') or 'N/D'}",
        f"Origen puerto: {alert.get('src_port') if alert.get('src_port') is not None else 'N/D'}",
        f"Destino: {alert.get('dst') or 'N/D'}",
        f"Destino puerto: {alert.get('dst_port') if alert.get('dst_port') is not None else 'N/D'}",
        f"Dominio: {alert.get('domain') or 'N/D'}",
        f"Protocolo: {alert.get('protocol') or 'N/D'}",
        f"Flags TCP: {alert.get('tcp_flags') or 'N/D'}",
        f"Timestamp: {alert.get('timestamp')}",
    ])

    if alert.get('type') == 'arp_spoof':
        lines.extend([
            '',
            'Detalle ARP spoof:',
            f"  MAC esperada: {alert.get('expected_mac')}",
            f"  MAC observada: {alert.get('actual_mac')}",
        ])

    evidence = alert.get('evidence')
    if evidence:
        lines.extend(['', 'Evidencia:'])
        lines.append(json.dumps(evidence, indent=2, ensure_ascii=False))

    if alert.get('blacklist_note'):
        lines.extend(['', f"Nota de blacklist: {alert['blacklist_note']}"])

    if whois_result:
        contacts = whois_result.get('abuse_contacts') or []
        lines.extend([
            '',
            'Consulta forense Abuse/Whois',
            f"Objetivo: {whois_result.get('target')}",
            f"Contactos abuse: {', '.join(contacts) if contacts else 'No encontrados'}",
            '',
            'Salida whois resumida:',
            (whois_result.get('raw') or '')[:3000],
        ])

    if EMAIL_COOLDOWN > 0:
        lines.extend([
            '',
            f"(Las alertas repetidas con la misma firma se silencian durante {EMAIL_COOLDOWN}s para evitar spam.)",
        ])

    return '\n'.join(lines)


def send_alert_email(alert, whois_result=None):
    if not ADMIN_EMAIL:
        print('No ADMIN_EMAIL configurado, omitiendo envío de correo')
        return False
    if not SMTP_HOST and not OAUTH_ENABLED:
        print('No SMTP_HOST ni credenciales OAuth configuradas, omitiendo envío de correo')
        return False

    signature = _alert_signature(alert)
    if not _should_send(signature):
        print(f'Alerta duplicada silenciada por dedupe ({EMAIL_COOLDOWN}s): {signature}')
        return False

    subject = _alert_subject(alert)
    return send_email(subject, format_alert_body(alert, whois_result))
