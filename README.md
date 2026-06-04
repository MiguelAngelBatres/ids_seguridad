# IDS Seguridad

IDS sencillo en Flask para registrar eventos de red, comparar contra listas blanca/negra y generar alertas.

## Estructura

- `app/main.py`: aplicación web Flask y rutas.
- `app/monitor.py`: captura/simulación de eventos, whitelist, blacklist, reportes y alertas.
- `app/emailer.py`: envío opcional de correos SMTP.
- `app/utils.py`: validación de IP/MAC, JSON y consulta `whois`.
- `app/templates/`: pantallas web.
- `data/`: archivos JSON persistentes.

## Configuración

1. Crea un entorno virtual:

```bash
python -m venv .venv
source .venv/bin/activate
```

2. Instala dependencias:

```bash
pip install -r requirements.txt
```

3. Crea tu archivo `.env`:

```bash
cp .env.example .env
```

Variables importantes:

- `PORT`: puerto web, por defecto `5000`.
- `FLASK_DEBUG`: `1` activa modo debug.
- `FLASK_SECRET`: llave para sesiones y mensajes flash.
- `SCAPY_ENABLE`: `0` usa simulación; `1` usa captura real.
- `SCAPY_IFACE`: interfaz de red para captura real, por ejemplo `eth0`.
- `SCAPY_BPF`: filtro BPF, por ejemplo `udp port 53 or tcp port 80`.
- `SMTP_*` y `ADMIN_EMAIL`: correo de alertas. Si no están configuradas, el sistema registra la alerta y omite el correo.

## Correr localmente

Modo simulación:

```bash
python -m app.main
```

Abre `http://localhost:5000`.

Modo captura real:

```bash
SCAPY_ENABLE=1 sudo -E python -m app.main
```

La captura real necesita permisos de red (`NET_RAW`/`NET_ADMIN`) y puede requerir `tcpdump`/`libpcap` y `whois` instalados en el sistema.

## Debug

Opción simple:

```bash
FLASK_DEBUG=1 python -m app.main
```

Para depurar desde VS Code/PyCharm, usa:

- módulo: `app.main`
- directorio de trabajo: raíz del proyecto
- variables de entorno: las de `.env`
- breakpoint inicial recomendado: `app/main.py` en la ruta que estás probando o `app/monitor.py` en `_handle_event`.

Nota: `use_reloader=False` está configurado para que Flask no arranque dos monitores durante debug.

## Docker

```bash
docker compose up --build
```

El servicio expone el puerto `5000` en el host, monta `./data:/app/data` y agrega capacidades de red para captura real.

En Docker Desktop en Windows, `network_mode: host` no es compatible, por lo que la aplicación debe accederse en `http://localhost:5000`.

Para probar sin captura, deja `SCAPY_ENABLE=0`.

## Endpoints

- `/`: panel principal con alertas.
- `/whitelist`: alta/baja de IP o MAC permitidas.
- `/reports`: eventos registrados.
- `/api/start`: arranca el monitor si no está corriendo.

Ver también `MANUAL_USUARIO.md` y `DOCUMENTACION_SEGURA.md`.
