# Documentación Segura — IDS Seguridad

---

## 1. Visión General del Sistema

Sistema detector de intrusiones (IDS) de red, pasivo y basado en firmas y heurísticas. Opera como un sensor de red que captura tráfico, lo analiza contra listas de control (blanca/negra) y motores de detección, y genera alertas con notificación opcional por correo electrónico. Incluye una interfaz web de administración y monitoreo en tiempo real.

**Naturaleza pasiva:** El sistema es exclusivamente de monitoreo (Wireshark-like). No modifica automáticamente ninguna lista de control; toda administración de entidades confiables o bloqueadas es realizada manualmente por el administrador a través de la interfaz web o edición directa de archivos JSON.

---

## 2. Arquitectura General

### 2.1 Capas del modelo OSI involucradas

| Capa OSI            | Protocolos/Datos   | Uso en el sistema                                                             |
|---------------------|--------------------|-------------------------------------------------------------------------------|
| Capa 2 (Enlace)     | MAC addresses, ARP | Lista blanca por MAC, detección de ARP spoofing                               |
| Capa 3 (Red)        | IPv4, ICMP         | Lista blanca por IP, lista negra IPs maliciosas, detección de inundación ICMP |
| Capa 4 (Transporte) | TCP, UDP           | Detección de escaneo de puertos (SYN flood, conexiones a puertos sensibles)   |
| Capa 7 (Aplicación) | HTTP, DNS          | Registro de dominios consultados, hosts HTTP, listas negras por dominio       |

### 2.2 Diagrama de flujo de datos (conceptual)

```
[Fuente de paquetes]
      |
      v
[Motor de captura] — Dos modalidades:
      |   A) Captura real: interfaz de red en modo promiscuo
      |   B) Simulación: generación periódica de eventos sintéticos
      |
      v
[Procesador de paquetes] — Desensamblado de capas:
      |   - Ethernet: MAC origen/destino
      |   - ARP: IP/MAC del emisor
      |   - IP: direcciones origen/destino, protocolo
      |   - TCP/UDP: puertos origen/destino, banderas TCP
      |   - DNS: nombre de consulta
      |   - HTTP: encabezado Host
      |
      v
[Motor de análisis] — Evaluación secuencial contra:
      1. Lista blanca (whitelist)
      2. Lista negra (blacklist + fuentes externas de inteligencia)
      3. Detector de ARP spoofing
      4. Motor heurístico (anomalías de comportamiento)
      |
      v
[Generador de alertas] — Cuatro tipos de alerta:
      |   - unauthorized_device
      |   - threat_intel
      |   - arp_spoof
      |   - heuristic
      |
      v
[Persistencia y notificación]
      - Archivos JSON en disco (bitácora, alertas, listas)
      - (Opcional) Correo electrónico con detalles y consulta whois
```

### 2.3 Componentes del sistema

| Componente         | Responsabilidad                                          |
|--------------------|----------------------------------------------------------|
| Web server (Flask) | Interfaz de usuario, API REST, gestión de datos          |
| Monitor            | Captura/análisis en segundo plano, evaluación de eventos |
| Emailer            | Notificación de alertas vía SMTP/OAuth2                  |
| Heuristics         | Detección de anomalías basada en ventanas deslizantes    |
| Utilidades         | Validación IP/MAC, consulta whois, E/S JSON              |

---

## 3. Modalidades de Captura

### 3.1 Captura real (Scapy)

El sistema puede utilizar la biblioteca Scapy para capturar paquetes directamente desde una interfaz de red en modo promiscuo. Se aplica un filtro BPF configurable para limitar el tráfico capturado (por defecto: tráfico IP, ARP, DNS y HTTP). Requiere permisos de administrador (NET_RAW, NET_ADMIN) y las herramientas tcpdump/libpcap instaladas en el sistema.

Por cada paquete capturado, se extraen las siguientes capas si están presentes:
- **Ethernet:** direcciones MAC origen y destino
- **ARP:** dirección IP y MAC del emisor
- **IP:** direcciones origen/destino, protocolo (TCP=6, UDP=17, ICMP=1)
- **TCP:** puertos origen/destino, banderas (SYN, ACK, FIN, RST, PSH, URG)
- **UDP:** puertos origen/destino
- **DNS:** nombre consultado (qname)
- **HTTP:** encabezado Host extraído de la carga útil

### 3.2 Captura simulada

Cuando no se dispone de permisos de captura (entornos de desarrollo/pruebas), el sistema genera eventos sintéticos cada cierto intervalo configurable. Los eventos simulan tráfico de red realista: IPs/MACs aleatorias dentro de rangos locales configurados, protocolos variados (TCP, UDP, ICMP, ARP, DNS, HTTP), y ocasionalmente tráfico malicioso que activa los distintos tipos de alerta.

---

## 4. Estructuras de Datos y Persistencia

Toda la información persistente se almacena en archivos JSON dentro de un directorio dedicado (`data/`). Los archivos se crean automáticamente si no existen.

| Archivo          | Propósito                         | Estructura conceptual                                                                       |
|------------------|-----------------------------------|---------------------------------------------------------------------------------------------|
| `whitelist.json` | Lista de dispositivos autorizados | Arreglo de entradas con IP, MAC (opcional), nota descriptiva, identificador único           |
| `blacklist.json` | Lista de IPs/dominios peligrosos  | Arreglo de entradas con IP (o host/dominio), nivel de riesgo, nota                          |
| `reports.json`   | Bitácora de eventos de red        | Arreglo de eventos con timestamp, IPs, MACs, puertos, protocolo, flags TCP, tamaño, dominio |
| `alerts.json`    | Registro de alertas generadas     | Arreglo de alertas con UUID, timestamp, tipo, IPs involucradas, evidencia, nivel de riesgo  |

El sistema mantiene una copia en memoria de todos los datos para acceso rápido. Un hilo en segundo plano sincroniza los cambios a disco cada pocos segundos, con mecanismos de exclusión mutua para garantizar consistencia en un entorno multihilo.

---

## 5. Motor de Listas de Control

### 5.1 Lista Blanca (Whitelist)

Propósito: Definir qué dispositivos están autorizados en la red monitoreada.

**Validación de pertenencia:** Dado un evento, se verifica si su dirección IP origen o MAC origen coincide con alguna entrada de la lista blanca. El sistema soporta:
- Coincidencia exacta de IP
- Coincidencia CIDR (ej. 192.168.0.0/24)
- Coincidencia exacta de MAC (formato normalizado xx:xx:xx:xx:xx:xx)

Una entrada puede especificar solo IP, solo MAC, o ambos. Cuando se especifican ambos, la coincidencia puede ser por cualquiera de los dos campos.

### 5.2 Lista Negra (Blacklist)

Propósito: Identificar destinos maliciosos conocidos (C2 de botnets, escáneres, malware).

El sistema mantiene dos subíndices en memoria para acceso O(1):
- **Índice de IPs maliciosas**
- **Índice de dominios maliciosos**

**Actualización desde fuentes externas:** El sistema descarga periódicamente (por defecto cada 24 horas) listas de inteligencia de amenazas desde dos fuentes públicas:
1. **Feodo Tracker** (abuse.ch) — IPs de servidores C2 de botnets
2. **CINS Army** (cinsscore.com) — IPs de escáneres/malware

Las entradas descargadas se fusionan con las entradas añadidas manualmente por el administrador. Las entradas manuales nunca son sobrescritas ni eliminadas por las actualizaciones automáticas.

---

## 6. Tipos de Alerta y Criterios de Activación

### 6.1 unauthorized_device

Se activa cuando la dirección IP o MAC de origen del evento **no está registrada en la lista blanca** y, además, la IP origen pertenece a las redes locales configuradas.

**Justificación:** Cualquier dispositivo no autorizado que aparece en la red debe ser reportado inmediatamente.

**Riesgo asignado:** "Equipo no registrado en lista blanca".

### 6.2 threat_intel

Se activa cuando la **IP destino** o el **dominio destino** del evento coincide con alguna entrada de la lista negra.

**Procesamiento adicional:** El sistema realiza una consulta WHOIS del host destino para extraer contactos de abuso (abuse contacts) e incluirlos en la notificación.

**Riesgo asignado:** Determinado por la entrada de la lista negra (ej. "Botnet C2", "Escáner malicioso").

### 6.3 arp_spoof

Se activa cuando la **IP origen está en la lista blanca** pero la **dirección MAC observada en el paquete difiere de la MAC registrada** para esa IP en la lista blanca.

**Condición:** Solo aplica a entradas de lista blanca que tienen tanto IP como MAC especificados.

**Justificación:** Este es un indicador clásico de suplantación ARP (ARP cache poisoning).

**Riesgo asignado:** "Posible ARP spoofing".

### 6.4 heuristic

Se activa cuando el motor heurístico detecta una anomalía estadística en el tráfico de una IP origen **no autorizada** (para evitar falsos positivos de escaneo local legítimo). Se suprimen para fuentes en lista blanca.

Las cuatro firmas heurísticas son:

| Firma       | Disparador                                                      | Ventana | Umbral              |
|-------------|-----------------------------------------------------------------|---------|---------------------|
| Port scan   | Múltiples puertos TCP destino distintos                         | 60 s    | ≥ 15 puertos únicos |
| ICMP flood  | Alta tasa de paquetes ICMP                                      | 30 s    | ≥ 20 paquetes       |
| SYN flood   | Alta tasa de SYN sin ACK (half-open)                            | 10 s    | ≥ 50 SYN            |
| Brute force | Conexiones a puertos sensibles (SSH, RDP, SMB, SMTP, SQL, etc.) | 60 s    | ≥ 20 conexiones     |

**Cooldown:** Cada alerta heurística tiene un período de enfriamiento (por defecto 5 minutos) para evitar notificaciones repetitivas de la misma fuente y mismo tipo de anomalía.

---

## 7. Motor Heurístico

Mantiene por cada dirección IP fuente una **ventana deslizante en memoria** con los eventos recientes de dicha fuente. Las ventanas se podan periódicamente para eliminar eventos expirados, y el estado total está acotado superiormente para evitar desbordamiento de memoria.

**Algoritmo conceptual:**
1. Al recibir un evento, se asigna a la ventana de su IP fuente
2. Se eliminan eventos más antiguos que la ventana de tiempo configurada
3. Se ejecutan secuencialmente las cuatro pruebas de detección
4. Si alguna prueba se activa y no está en período de cooldown, se genera una alerta y se registra la firma en la cola de cooldown
5. Se retorna la lista de alertas generadas (pueden ser múltiples)

Todos los umbrales y ventanas son configurables mediante variables de entorno, permitiendo ajustar la sensibilidad del sistema sin modificar el código.

---

## 8. Notificación de Alertas

### 8.1 Persistencia local

Toda alerta se almacena inmediatamente en el archivo `alerts.json` con un UUID único, timestamp preciso, tipo, direcciones involucradas y metadatos de evidencia.

El sistema mantiene un límite máximo de eventos en memoria; cuando se alcanza, se descartan primero las alertas de tipo `unauthorized_device` por ser las de menor prioridad, preservando las más críticas.

### 8.2 Notificación por correo electrónico

Si se configuran los parámetros SMTP, el sistema envía un correo electrónico al administrador por cada alerta generada. El envío es asíncrono (hilo separado) para no bloquear el procesamiento de eventos.

**Cuerpo del correo:** Incluye:
- Tipo de alerta y nivel de riesgo
- Direcciones IP/MAC origen y destino
- Timestamp y evidencia estructurada (JSON)
- Detalles específicos del tipo (para ARP spoofing: MAC esperada vs. real; para heurística: subtipo y firma; para threat_intel: resultado WHOIS y contactos de abuso)

**Mecanismos de control:**
- **Deduplicación:** Alertas con la misma firma (tipo + IPs involucradas) no generan correo duplicado dentro de una ventana configurable (por defecto 5 minutos).
- **Límite de tasa:** Máximo de correos por minuto configurable (por defecto 6/minuto) para evitar ser marcado como spam.

### 8.3 Métodos de autenticación SMTP

El sistema soporta dos métodos:
1. **Autenticación clásica** (usuario/contraseña): Compatible con GMail (App Password), Outlook y servidores SMTP genéricos.
2. **OAuth2 (XOAUTH2):** Específicamente para GMail, usando refresh token y client credentials.

SSL implícito (puerto 465) y STARTTLS (puerto 587) son detectados automáticamente según el puerto configurado.

---

## 9. Interfaz Web

Aplicación web de una sola página (SPA) que consume la API REST del servidor Flask. No requiere recarga de página para actualizaciones.

### 9.1 Pantallas

| Pantalla                 | Funcionalidad                                                                                              |
|--------------------------|------------------------------------------------------------------------------------------------------------|
| **Dashboard (Overview)** | KPIs: total alertas, total eventos, IPs únicas detectadas, amenazas críticas. Gráficos,Actividad reciente. |
| **Alertas**              | Tabla filtrable por tipo con buscador. Selección múltiple para borrado. Copia de filtro Wireshark.         |
| **Reportes (bitácora)**  | Tabla de eventos con filtro por protocolo y búsqueda. Copia de filtro Wireshark.                           |
| **Lista Blanca**         | Formulario de alta (IP, MAC, nota). Listado con eliminación.                                               |
| **Lista Negra**          | Formulario de alta (IP/host/dominio, riesgo, nota). Listado con eliminación.                               |

### 9.2 Actualización en tiempo real

La interfaz consulta la API REST cada 3 segundos para obtener nuevas alertas y eventos (solo los cambios incrementales mediante el parámetro `since`). La lista blanca se refresca cada 5 segundos. Adicionalmente, cada 10 segundos se realiza una recarga completa para reconciliar el estado.

### 9.3 Gráficos

Cuatro componentes gráficos implementados sin dependencias externas (SVG puro):
- **Sparkline:** Minigráfico de línea para tendencias de KPIs
- **Área temporal:** Gráfico de área con puntos para alertas en el tiempo
- **Dona:** Gráfico de anillo para distribuciones (tipo de alerta, nivel de riesgo)
- **Barras horizontales:** Ranking de IPs o protocolos más frecuentes

---

## 10. API REST

| Método | Ruta                          | Propósito                                           |
|--------|-------------------------------|-----------------------------------------------------|
| GET    | `/`                           | Panel principal con datos actuales                  |
| GET    | `/api/start`                  | Iniciar el monitor en segundo plano                 |
| GET    | `/api/alerts?since=timestamp` | Obtener alertas (incremental)                       |
| POST   | `/api/alerts/clear`           | Limpiar alertas (con filtro opcional por tipo)      |
| POST   | `/api/alerts/delete_batch`    | Borrar alertas específicas por lista de IDs         |
| GET    | `/api/reports?since=timestamp`| Obtener eventos (incremental)                       |
| POST   | `/api/reports/clear`          | Limpiar eventos (con filtro opcional por protocolo) |
| GET    | `/api/whitelist`              | Obtener lista blanca                                |
| POST   | `/api/whitelist`              | Añadir entrada a lista blanca                       |
| POST   | `/api/whitelist/remove`       | Eliminar entrada de lista blanca                    |
| GET    | `/api/blacklist`              | Obtener lista negra                                 |
| POST   | `/api/blacklist`              | Añadir entrada a lista negra                        |
| POST   | `/api/blacklist/remove`       | Eliminar entrada de lista negra                     |

---

## 11. Seguridad

### 11.1 Protección de credenciales

- No existen credenciales hardcodeadas. Toda configuración sensible se lee de variables de entorno.
- Se provee un archivo de ejemplo (`.env.example`) con la documentación de todas las variables.
- Como medida adicional, el archivo `.env` puede cifrarse con OpenSSL (AES-256-CBC) y descifrarse solo en tiempo de despliegue.

### 11.2 Límites del sistema (consideraciones de seguridad)

- El archivo `.env` contiene credenciales SMTP en texto plano en el sistema de archivos. Medida de mitigación: incluirlo en `.gitignore` y `.dockerignore`.
- Los archivos JSON de datos no están cifrados en reposo. Medida de mitigación: pueden almacenarse en un volumen cifrado o partición separada.
- El dashboard web no implementa autenticación de usuarios. Medida de mitigación: debe ejecutarse exclusivamente en redes internas aisladas.

---

## 12. Análisis Jurídico (México)

### 12.1 Marco legal aplicable

El monitoreo de tráfico en una red privada corporativa es legal bajo las siguientes condiciones:
- Existe una política de uso de recursos informáticos comunicada y aceptada por los empleados.
- El monitoreo se limita a lo necesario para fines de seguridad informática.
- Se preserva el principio de mínima intrusión.

### 12.2 Ley Federal de Protección de Datos Personales en Posesión de los Particulares (LFPDPPP)

Las direcciones IP pueden considerarse datos personales indirectos. Por tanto:
- Debe documentarse la base legal del tratamiento (interés legítimo del responsable para seguridad de la red).
- Deben implementarse medidas de seguridad administrativas, técnicas y físicas.
- Deben garantizarse los derechos ARCO (Acceso, Rectificación, Cancelación, Oposición).

### 12.3 Recomendación

Elaborar y publicar una "Política de Monitoreo y Tratamiento de Datos" que especifique: finalidad del monitoreo, base legal, responsables del tratamiento, medidas de seguridad implementadas, plazo de conservación de las bitácoras, procedimiento para ejercicio de derechos ARCO, y canales de contacto.

---

## 13. Configuración del Entorno

El sistema se configura exclusivamente mediante variables de entorno. Las categorías de configuración son:

| Categoría         | Variables principales                                                          |
|-------------------|--------------------------------------------------------------------------------|
| Flask             | `FLASK_DEBUG`, `FLASK_SECRET`, `PORT`                                          |
| Captura           | `SCAPY_ENABLE`, `SCAPY_IFACE`, `SCAPY_BPF`, `SCAPY_PROMISC`                    |
| Redes locales     | `IDS_LOCAL_NETS` (CIDRs separados por coma)                                    |
| Correo SMTP       | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `ADMIN_EMAIL` |
| Correo OAuth2     | `EMAIL_USER`, `CLIENT_ID`, `CLIENT_SECRET`, `OAUTH_REFRESH_TOKEN`              |
| Control de correo | `EMAIL_COOLDOWN`, `EMAIL_RATE_MAX`                                             |
| Heurísticas       | `HEUR_PORT_SCAN_THRESHOLD`, `HEUR_PORT_SCAN_WINDOW`, `HEUR_ICMP_THRESHOLD`, `HEUR_ICMP_WINDOW`, `HEUR_SYN_THRESHOLD`, `HEUR_SYN_WINDOW`, `HEUR_BRUTE_THRESHOLD`, `HEUR_BRUTE_WINDOW`, `HEUR_COOLDOWN`, `HEUR_SENSITIVE_PORTS`                                         |

Todas las variables heurísticas tienen valores por defecto documentados en el archivo de ejemplo.

---

## 14. Despliegue

### 14.1 Local (desarrollo/pruebas)

Se requiere Python 3.12+ con las dependencias: Flask, python-dotenv, scapy. El sistema se inicia como módulo Python y el servidor web escucha en `0.0.0.0:$PORT` con `use_reloader=False` para evitar la duplicación del hilo monitor.

### 14.2 Docker

El sistema incluye Dockerfile (base python:3.12-slim con tcpdump y whois) y docker-compose.yml con las capacidades de red necesarias (NET_ADMIN, NET_RAW) y montaje bind del directorio de datos para persistencia.

### 14.3 Dependencias del sistema

- **tcpdump / libpcap:** Necesarios para captura real con Scapy
- **whois:** Necesario para consultas WHOIS en alertas threat_intel

---

## 15. Script de Prueba de Amenazas

Se incluye un script bash diseñado para ejecutarse desde una máquina diferente en la misma red. Genera tráfico de prueba que activa cada uno de los cuatro tipos de alerta:

1. **threat_intel:** Conexiones HTTP/DNS a IPs incluidas en la lista negra
2. **Port scan:** Conexiones a un rango de puertos (20-50) en la máquina IDS
3. **ICMP flood:** Envío masivo de pings
4. **Brute force:** Múltiples conexiones a puertos SSH (22) y RDP (3389)

---

## 16. Glosario de Términos

| Término      | Definición                                                       |
|--------------|------------------------------------------------------------------|
| IDS          | Intrusion Detection System — Sistema de Detección de Intrusiones |
| BPF          | Berkeley Packet Filter — Filtro de paquetes a nivel de interfaz  |
| Whois        | Protocolo de consulta de registro de dominios/IPs                |
| ARP spoofing | Técnica de suplantación de identidad en redes Ethernet           |
| CIDR         | Classless Inter-Domain Routing — Notación de subred              |
| OAuth2       | Protocolo de autorización para delegación de acceso              |
| STARTTLS     | Extensión para actualizar conexión SMTP a cifrada                |
| SYN flood    | Ataque de denegación de servicio mediante paquetes SYN           |
| Scapy        | Biblioteca Python para manipulación de paquetes de red           |
| KPI          | Key Performance Indicator — Indicador clave de rendimiento       |
| UUID         | Universal Unique Identifier — Identificador único universal      |
