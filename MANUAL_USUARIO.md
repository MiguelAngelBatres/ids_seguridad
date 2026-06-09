# Manual de Usuario — IDS Seguridad

**Sistema Operativo recomendado:** Linux (Ubuntu 22.04+, Debian 11+, o cualquier distribución basada en Debian).  
*También funciona en Windows con WSL2 o Docker Desktop, pero la captura real de paquetes requiere libpcap, que es nativa de Linux/Unix.*

---

## 1. Guía de Instalación y Requisitos

### 1.1 Prerrequisitos del sistema

| Componente | Versión mínima | Notas |
|---|---|---|
| Python | 3.8+ | Verificar con `python3 --version` |
| pip | 21+ | Normalmente incluido con Python |
| libpcap | 1.9+ | Necesario solo para captura real de paquetes |
| tcpdump | 4.9+ | Opcional, útil para depurar captura |
| whois | 5.5+ | Opcional, para consultas WHOIS en alertas threat_intel |

**Instalación de dependencias del sistema (Linux):**

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv tcpdump whois libpcap-dev
```

### 1.2 Dependencias de Python

El archivo `requirements.txt` contiene:

```
Flask
python-dotenv
scapy
```

Flask y python-dotenv son obligatorios siempre. Scapy es necesario únicamente si se desea captura real de paquetes (`SCAPY_ENABLE=1`).

### 1.3 Instalación paso a paso

```bash
# 1. Descomprimir el proyecto y entrar al directorio
cd ids_seguridad

# 2. Crear entorno virtual
python3 -m venv .venv
source .venv/bin/activate

# 3. Instalar dependencias Python
pip install -r requirements.txt

# 4. ¡Ejecutar! (el .env ya está preconfigurado)
python -m app.main
```

> **Nota:** El archivo `.env` incluido en el ZIP ya está listo para usar en **modo simulación** (`SCAPY_ENABLE=0`). No necesita editar nada para que funcione. Si desea captura real o correo SMTP, consulte las secciones siguientes.

> ⚠️ **Importante:** Para recibir los correos de alerta, cambie `ADMIN_EMAIL` en el `.env` por **su propio correo**. Por defecto viene configurado con el correo del desarrollador para pruebas.

La aplicación arranca en modo **simulación**, generando eventos falsos cada 2 segundos para probar el sistema sin necesidad de capturar tráfico real ni permisos especiales.

### 1.4 Configuración del servidor SMTP (correo de alertas)

El sistema puede enviar alertas por correo electrónico. Si no se configura, las alertas solo se guardan en `data/alerts.json` y se muestran en la interfaz web.

> ⚠️ **Importante:** Cambie `ADMIN_EMAIL=al350553@edu.uaa.mx` por **su propio correo** en el `.env`. Así las alertas le llegarán a usted y no al desarrollador.

Edite el archivo `.env` y complete las variables según su proveedor:

#### Opción A — Gmail con "Contraseña de aplicación" (recomendada para Gmail)

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_USE_SSL=1
SMTP_USER=su.correo@gmail.com
SMTP_PASS=xxxx xxxx xxxx xxxx
ADMIN_EMAIL=admin@example.com
```

> **Importante:** En Gmail debe activar "Verificación en dos pasos" y generar una "Contraseña de aplicación" desde https://myaccount.google.com/apppasswords. No use su contraseña normal.

#### Opción B — Gmail con OAuth2 (XOAUTH2)

Más segura, requiere registrar una aplicación en Google Cloud Console:

```
EMAIL_USER=su.correo@gmail.com
CLIENT_ID=xxxxx.apps.googleusercontent.com
CLIENT_SECRET=GOCSPX-xxxxx
OAUTH_REFRESH_TOKEN=1//0xxxxx
ADMIN_EMAIL=admin@example.com
```

#### Opción C — Outlook / Office365

```
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USER=su.correo@outlook.com
SMTP_PASS=su_contraseña
ADMIN_EMAIL=admin@example.com
```

#### Opción D — Servidor SMTP genérico (STARTTLS)

```
SMTP_HOST=smtp.mi-dominio.com
SMTP_PORT=587
SMTP_USER=usuario
SMTP_PASS=clave
ADMIN_EMAIL=admin@example.com
```

### 1.5 Captura real de paquetes (opcional)

Para capturar tráfico real de red en lugar de usar simulación, **debe ejecutar como root**:

```bash
SCAPY_ENABLE=1 sudo -E python -m app.main
```

Opcionalmente puede especificar interfaz y filtro:

```bash
SCAPY_ENABLE=1 SCAPY_IFACE=wlan0 sudo -E python -m app.main
```

> **Nota:** La captura real requiere permisos de superusuario (root) o capacidades `CAP_NET_RAW` + `CAP_NET_ADMIN`. Sin permisos, la aplicación mostrará un mensaje de error claro y **caerá automáticamente a modo simulación** para que siga funcionando.

### 1.6 Instalación con Docker

```bash
# Construir y ejecutar
docker compose up --build
```

El servicio queda accesible en `http://localhost:5000`. Los datos persisten en `data/` gracias al bind mount del volumen.

Para usar captura real con Docker, edite `docker-compose.yml` y agregue `network_mode: host`.

---

## 2. Instrucciones de Operación

### 2.1 Acceso a la interfaz web

Abra su navegador y vaya a:

```
http://localhost:5000
```

Verá el panel principal con tres secciones:

```
┌──────────────────────────────────────────────────────────────────────┐
│  IDS Console                                   [En vivo] ●          │
│──────────────────────────────────────────────────────────────────────│
│                                                                      │
│  ┌─ Alertas ───────────────────────────────────────────────────────┐ │
│  │  Mapa de calor de alertas (últimas 24h)                        │ │
│  │  ████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░                       │ │
│  │                                                                 │ │
│  │  Lista de alertas recientes...                                 │ │
│  └────────────────────────────────────────────────────────────────-┘ │
│                                                                      │
│  ┌─ Dispositivos Whitelist ───────────────────────────────────────┐ │
│  │  192.168.1.100 - aa:bb:cc:dd:ee:ff - Servidor Web             │ │
│  │  192.168.1.39 - (sin MAC) - Mi computadora                    │ │
│  └────────────────────────────────────────────────────────────────-┘ │
│                                                                      │
│  ┌─ Eventos Recientes ─────────────────────────────────────────────┐ │
│  │  09/Jun 12:34:56  192.168.1.39 → 203.0.113.66  HTTP           │ │
│  │  09/Jun 12:34:54  192.168.1.39 → 8.8.8.8      DNS            │ │
│  └────────────────────────────────────────────────────────────────-┘ │
│                                                                      │
│  [Whitelist]  [Reportes]  [Limpiar Alertas]                         │
└──────────────────────────────────────────────────────────────────────┘
```

*(Inserte aquí captura de pantalla del panel principal)*

### 2.2 Dar de alta una IP/MAC en la lista blanca

La lista blanca (whitelist) contiene los dispositivos autorizados en la red. Cualquier tráfico desde una IP o MAC **no registrada** en esta lista generará una alerta de tipo `unauthorized_device`.

**Paso a paso:**

1. En el panel principal, haga clic en el enlace **"Whitelist"** (o navegue a `http://localhost:5000/whitelist`).

2. Verá un formulario como este:

   ```
   ┌─────────────────────────────────────┐
   │  Lista Blanca                       │
   │─────────────────────────────────────│
   │                                     │
   │  IP:   [_________________________]  │
   │  MAC:  [_________________________]  │
   │  Nota: [_________________________]  │
   │                                     │
   │  [Agregar]                          │
   │                                     │
   │  ─ Entradas ─────────────────────── │
   │  • 192.168.1.100 - aa:bb:cc:dd:    │
   │    ee:ff - Servidor Web  [Eliminar] │
   │  • 192.168.1.39 - (sin MAC) -      │
   │    Mi compu  [Eliminar]             │
   └─────────────────────────────────────┘
   ```

   *(Inserte aquí captura de pantalla de la página Whitelist)*

3. Complete los campos:
   - **IP:** Dirección IP del dispositivo (ej: `192.168.1.100`)
   - **MAC:** Dirección MAC del dispositivo (ej: `aa:bb:cc:dd:ee:ff`). Puede dejarse vacío si solo se quiere registrar por IP.
   - **Nota:** Descripción opcional (ej: `Servidor de producción`)

4. Presione **"Agregar"**.

5. Si los datos son válidos, la entrada aparecerá en la lista de abajo con un mensaje de confirmación.

> **Reglas de validación:**
> - Debe proporcionar al menos una IP o una MAC.
> - El formato de IP debe ser válido (IPv4 o IPv6).
> - La MAC debe tener formato `xx:xx:xx:xx:xx:xx`.
> - No se permiten IPs ni MACs duplicadas.

### 2.3 Eliminar una entrada de la lista blanca

Junto a cada entrada hay un botón **"Eliminar"**. Haga clic en él para remover el dispositivo de la lista blanca. A partir de ese momento, su tráfico volverá a generar alertas `unauthorized_device`.

### 2.4 Ver los reportes de eventos

Cada paquete o evento de red capturado se registra en la sección **Reportes**.

1. Haga clic en el enlace **"Reportes"** del panel principal (o navegue a `http://localhost:5000/reports`).

2. Verá una tabla con todos los eventos capturados:

   ```
   ┌──────────────────────────────────────────────────────────────────┐
   │  Reportes                                       [En vivo] ●     │
   │  47 eventos capturados.                       [Limpiar lista]   │
   │──────────────────────────────────────────────────────────────────│
   │  ┌─────────────────────────────────────────────────────────────┐│
   │  │  Hora      │ Origen        │ Destino       │Proto│Dom│Tam  ││
   │  │────────────┼───────────────┼───────────────┼─────┼───┼─────││
   │  │ [filtro]   │ [filtro]      │ [filtro]      │[filt]│[f]│[f] ││
   │  ├────────────┼───────────────┼───────────────┼─────┼───┼─────││
   │  │ 1718000000 │ 192.168.1.39 │ 203.0.113.66  │HTTP │ - │ 1420││
   │  │            │ aa:bb:cc:..  │               │     │   │     ││
   │  │ 1718000002 │ 192.168.1.39 │ 8.8.8.8       │DNS  │go..│ 78  ││
   │  └─────────────────────────────────────────────────────────────┘│
   └──────────────────────────────────────────────────────────────────┘
   ```

   *(Inserte aquí captura de pantalla de la página Reportes)*

3. Cada fila muestra: **marca de tiempo**, **IP/MAC origen** (con puerto si aplica), **IP/MAC destino** (con puerto), **protocolo**, **dominio** (si es DNS/HTTP) y **tamaño** del paquete.

4. **Filtros:** Use los campos en la segunda fila del encabezado para buscar eventos por cualquier columna. Por ejemplo, escriba `DNS` en la columna Proto para ver solo consultas DNS.

5. **Actualización en vivo:** La tabla se actualiza automáticamente cada 3 segundos. Un indicador verde muestra "En vivo" cuando la conexión está activa.

6. **Limpiar reportes:** Use el botón "Limpiar lista de reportes" para borrar todos los eventos (útil antes de una prueba).

### 2.5 Interpretación de las alertas

El IDS genera **4 tipos de alertas**, todas visibles en el panel principal y opcionalmente enviadas por correo:

#### a) `unauthorized_device` — Dispositivo no autorizado

Se activa cuando un dispositivo con IP o MAC **no registrada en la whitelist** envía tráfico en la red local.

```
[Tipo]          unauthorized_device
[Riesgo]        Equipo no registrado en lista blanca
[Origen IP]     192.168.1.50
[Origen MAC]    ff:ee:dd:cc:bb:aa
```

> **Qué hacer:** Si el dispositivo es legítimo, agréguelo a la whitelist. Si es desconocido, investigue su procedencia.

#### b) `threat_intel` — Inteligencia de amenazas

Se activa cuando el tráfico se dirige a una IP, dominio o host **registrado en la blacklist**.

```
[Tipo]          threat_intel
[Riesgo]        Virus/Botnet
[Origen IP]     192.168.1.39
[Destino]       203.0.113.66
[Nota blacklist] Entrada de ejemplo
```

Para agregar entradas a la blacklist, edite directamente el archivo `data/blacklist.json`:

```json
[
  {
    "ip": "203.0.113.66",
    "host": "malicious.example",
    "risk": "Virus/Botnet",
    "note": "Entrada de ejemplo"
  }
]
```

> **Qué hacer:** Revise si el equipo interno está comprometido. Bloquee el destino en el firewall si es necesario.

#### c) `arp_spoof` — Suplantación ARP

Se activa cuando una IP que **sí está en la whitelist** aparece con una **MAC diferente** a la registrada.

```
[Tipo]          arp_spoof
[Riesgo]        Posible ARP spoofing: la IP de la lista blanca aparece con una MAC distinta
[Origen IP]     192.168.1.100
[MAC esperada]  aa:bb:cc:dd:ee:ff
[MAC observada] 11:22:33:44:55:66
```

> **Qué hacer:** Esto indica un posible ataque de ARP spoofing. Verifique cuál MAC es la correcta revisando el switch/router. Si la MAC observada no es legítima, hay un ataque en curso.

#### d) `heuristic` — Alerta heurística

El motor heurístico detecta patrones anómalos: escaneo de puertos, inundación ICMP/SYN, fuerza bruta, etc.

```
[Tipo]          heuristic
[Subtipo]       port_scan
[Riesgo]        Escaneo de puertos detectado
[Origen IP]     10.0.0.5
[Puertos]       22,80,443,3306,3389,5432
```

Tipos de detección heurística:

| Subtipo | Disparo | Umbral por defecto |
|---|---|---|
| `port_scan` | Misma IP consulta ≥15 puertos distintos en 60s | 15 puertos / 60s |
| `icmp_flood` | Misma IP envía ≥20 paquetes ICMP en 30s | 20 paquetes / 30s |
| `syn_flood` | Misma IP envía ≥50 SYN en 10s | 50 SYN / 10s |
| `brute_force` | Misma IP conecta a ≥20 puertos sensibles (22,23,3389,...) en 60s | 20 intentos / 60s |

> **Nota:** Las alertas heurísticas se **silencian** para fuentes en whitelist para evitar falsos positivos de escaneos internos legítimos.

---

## 3. Troubleshooting Básico

### 3.1 La aplicación no arranca

**Síntoma:** `python -m app.main` lanza un error de importación.

**Solución:** Verifique que el entorno virtual está activado y las dependencias instaladas:

```bash
source .venv/bin/activate
pip list | grep -E "Flask|scapy|python-dotenv"
```

Si falta algún paquete, ejecute:

```bash
pip install -r requirements.txt
```

### 3.2 Error "scapy import failed, falling back to simulation"

**Síntoma:** Al usar `SCAPY_ENABLE=1` aparece este mensaje.

**Solución:** Scapy no está instalado o falta libpcap:

```bash
pip install scapy
sudo apt install -y libpcap-dev
```

Si el problema persiste, ejecute como root:

```bash
SCAPY_ENABLE=1 sudo -E python -m app.main
```

### 3.3 No se capturan paquetes en modo real

**Síntoma:** La aplicación inicia pero no aparecen eventos en Reportes.

**Soluciones posibles:**

1. Verifique la interfaz de red:
   ```bash
   ip link show            # Listar interfaces disponibles
   SCAPY_IFACE=eth0 sudo -E python -m app.main
   ```

2. Verifique el filtro BPF:
   ```bash
   SCAPY_BPF="" sudo -E python -m app.main  # Sin filtro (captura todo)
   ```

3. Pruebe que scapy funciona por separado:
   ```bash
   sudo python3 -c "from scapy.all import sniff; sniff(count=5, timeout=5)"
   ```

4. Revise que no haya un firewall bloqueando la captura:
   ```bash
   sudo iptables -L
   ```

### 3.4 No llegan los correos de alerta

**Síntoma:** Las alertas se muestran en la interfaz web pero no se reciben por correo.

**Verificaciones:**

1. Revise el archivo `.env` — ¿están configuradas todas las variables SMTP?
   ```bash
   grep -E "^SMTP_|^ADMIN_EMAIL" .env
   ```

2. Pruebe la conexión SMTP manualmente:
   ```bash
   # Para servidores STARTTLS (puerto 587)
   openssl s_client -starttls smtp -connect smtp.gmail.com:587 -crlf

   # Para SSL (puerto 465)
   openssl s_client -connect smtp.gmail.com:465 -crlf
   ```

3. Active el modo debug para ver errores detallados de envío:
   ```bash
   FLASK_DEBUG=1 python -m app.main
   ```
   Los errores SMTP se imprimirán en la consola.

4. Si usa Gmail con "Contraseña de aplicación", asegúrese de que:
   - La verificación en dos pasos está activada.
   - La contraseña se generó desde https://myaccount.google.com/apppasswords.
   - No hay espacios al copiar la contraseña (tiene formato `xxxx xxxx xxxx xxxx`).

5. Si usa OAuth2, el refresh token puede haber expirado. Genere uno nuevo.

### 3.5 El correo de alerta llega a la carpeta de spam

**Síntoma:** Las alertas se envían correctamente pero aparecen en la carpeta de Spam/Correo no deseado.

**Soluciones:**

1. **Marque como "No es spam":** En Gmail/Outlook, abra el primer correo y seleccione "No es spam" o "Mover a la bandeja de entrada". Esto entrena el filtro.

2. **Agregue el remitente a la libreta de direcciones:** Agregue la dirección `SMTP_FROM` a sus contactos. En Gmail, cree un filtro para nunca enviar a spam los correos con el remitente del IDS.

3. **Configure SPF y DKIM en el dominio SMTP (si usa un dominio propio):**
   - **SPF:** Agregue un registro TXT en su DNS como `v=spf1 ip4:1.2.3.4 -all`
   - **DKIM:** Configure la firma DKIM en su servidor de correo

4. **Para Gmail (cuenta propia):** Si usa Gmail como remitente, los correos deberían entregarse normalmente. Si van a spam, probablemente el contenido del asunto ("[IDS] Amenaza...") activa filtros. Considere:
   - Cambiar `SMTP_FROM_NAME` a algo más genérico como "Sistema de Notificaciones".
   - Reducir la frecuencia de alertas (aumente `EMAIL_COOLDOWN` en `.env`).

5. **Verifique los encabezados del correo:** En Gmail, abra el correo → "Mostrar original" y revise `Authentication-Results`. Esto indicará si SPF, DKIM o DMARC están fallando.

### 3.6 Error "La IP ya existe en la lista blanca" o "La MAC ya existe"

**Síntoma:** Al agregar un dispositivo, el sistema rechaza la entrada.

**Solución:** Las IPs y MACs deben ser únicas en la whitelist. Si necesita actualizar una entrada (ej. cambiar la MAC asociada a una IP), elimine la entrada anterior y cree una nueva.

### 3.7 Error de permisos al usar Docker

**Síntoma:** Al hacer `docker compose up`, la captura real falla.

**Solución:** El contenedor necesita capacidades de red adicionales. El `docker-compose.yml` ya incluye `cap_add: [NET_ADMIN, NET_RAW]`. Si aun así falla, intente con `network_mode: host`:

```yaml
services:
  ids:
    ...
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
```

Y acceda al sistema en `http://localhost:5000`.

### 3.8 Los datos se pierden al reiniciar Docker

**Síntoma:** Las entradas de whitelist, alertas y reportes desaparecen tras `docker compose down && up`.

**Solución:** El directorio `data/` debe persistir. Verifique que el volumen está montado:

```yaml
volumes:
  - ./data:/app/data
```

Si usó `docker compose down -v`, el volumen se elimina. Use solo `docker compose down` (sin `-v`).

### 3.9 El motor heurístico no detecta nada

**Síntoma:** Se esperan alertas heurísticas pero no aparecen.

**Soluciones:**

1. Las alertas heurísticas están **silenciadas para fuentes en whitelist**. Si la IP origen está en la whitelist, no se generarán. Quite la IP de la whitelist para probar.

2. Revise los umbrales en `.env`:
   ```bash
   grep "^HEUR_" .env
   ```
   Reduzca temporalmente los umbrales para probar (ej: `HEUR_PORT_SCAN_THRESHOLD=3`).

3. La simulación (`SCAPY_ENABLE=0`) genera eventos genéricos que pueden no disparar heurísticas. Use captura real o modifique la simulación para generar tráfico que active las reglas.

### 3.10 La interfaz web no carga

**Síntoma:** El navegador muestra "No se puede conectar" o error de conexión.

**Verificaciones:**

```bash
# 1. ¿El proceso de Flask está corriendo?
ps aux | grep python

# 2. ¿El puerto está en uso?
ss -tlnp | grep 5000

# 3. ¿El firewall permite la conexión?
sudo ufw status
```

Si el puerto 5000 ya está ocupado, cambie el `PORT` en `.env`:

```
PORT=8080
```

---

## Apéndice: Estructura de datos

| Archivo | Propósito | Formato |
|---|---|---|
| `data/whitelist.json` | Dispositivos autorizados | JSON array |
| `data/blacklist.json` | IPs/dominios maliciosos | JSON array |
| `data/alerts.json` | Historial de alertas | JSON array |
| `data/reports.json` | Eventos de red capturados | JSON array |

Los archivos JSON se crean automáticamente si no existen. Puede editarlos manualmente con cualquier editor de texto, pero se recomienda usar la interfaz web para whitelist para evitar errores de sintaxis.

---

*Documento generado para el proyecto IDS Seguridad — Sistema de Detección de Intrusiones basado en Flask.*
