Manual de Usuario - IDS Seguridad

Sistema operativo recomendado: Linux (cualquier distribución moderna: Ubuntu, Debian, CentOS).

1) Guía de Instalación y Requisitos
- Requisitos del sistema: Python 3.8+, acceso a red y permisos para captura de paquetes si se usa libpcap.
- Dependencias: ver `requirements.txt` (Flask, python-dotenv). Para captura real de paquetes instalar `libpcap` y bibliotecas Python como `scapy` o `pyshark`.
- Configuración SMTP: configurar variables de entorno según `.env.example` (SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, ADMIN_EMAIL). No dejar credenciales en el código.

Instalación rápida:

1. Clonar el repositorio
2. Crear entorno virtual: python -m venv venv && source venv/bin/activate
3. Instalar dependencias: pip install -r requirements.txt
4. Copiar `.env.example` a `.env` y completar variables
5. Iniciar la aplicación: python -m app.main
 
 Captura de paquetes (modo real):
 
 - Para habilitar captura real con scapy, instale las dependencias nativas y configure permiso de captura (root o setcap):
 
	 - `pip install scapy`
	 - Ejecutar la aplicación como root o dar capacidades: `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)` (nota: revisar seguridad)
	 - Habilitar la captura con la variable de entorno: `SCAPY_ENABLE=1` y opcionalmente `SCAPY_IFACE=eth0` y `SCAPY_BPF="port 80 or port 53"`.
 
 Si no habilita `SCAPY_ENABLE`, la aplicación correra en modo simulación y generará eventos de ejemplo para probar la whitelist y alertas.

2) Instrucciones de Operación
- Acceder a la interfaz web en http://localhost:5000
- Para agregar una IP/MAC a la lista blanca: ir a "Lista Blanca", completar IP o MAC y presionar "Agregar".
- Para eliminar una entrada: presionar "Eliminar" junto a la entrada.
- Visualizar reportes: ir a "Reportes" para ver eventos registrados.
- Interpretación de alertas: en el panel principal aparecen alertas con timestamp, IP origen, destino y nivel de riesgo. Riesgo puede ser "Posible" o especificado si se detecta en la lista negra.

Capturas de pantalla (CLI simple)

La versión actual es una demo; para captura real se requiere permisos root y librerías adicionales.

3) Troubleshooting Básico
- Si no llegan correos: verificar `.env`, probar conexión SMTP con `telnet` o `openssl s_client`.
- Si los correos van a spam: pedir al administrador de correo añadir la dirección del remitente a lista segura, revisar encabezados y SPF/DKIM de la cuenta SMTP.
- Si la interfaz no carga: revisar que Flask esté corriendo y el puerto configurado.
- Permisos de captura: si la captura de paquetes falla, ejecutar como root o usar capacidades `setcap` en binarios que necesiten acceso a libpcap.
