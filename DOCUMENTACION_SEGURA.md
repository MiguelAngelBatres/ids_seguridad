Documentación Segura y Prerrequisitos

1) Arquitectura y Modelo OSI
- El sistema propuesto opera en capas 2/3 para listas blancas (MAC/IP) y en capa 7 para registros HTTP/DNS.
- Diagrama de flujo (simplificado):
  - Captura de paquetes -> Parseo (L2/L3/L7) -> Comparación con whitelist/blacklist -> Registro en bitácora -> Generación de alerta y envío de correo -> (Automatización) Consulta whois/abuse.

2) Protección de Credenciales
- No incluir contraseñas hardcoded en el código. Utilizar variables de entorno (`.env`) y un ejemplo está en `.env.example`.
- Para mayor seguridad, puede cifrarse el archivo de configuración con OpenSSL. Ejemplo rápido:

  - Crear archivo JSON config.json con credenciales
  - Cifrar: openssl enc -aes-256-cbc -salt -in config.json -out config.json.enc
  - Descifrar en tiempo de despliegue: openssl enc -d -aes-256-cbc -in config.json.enc -out config.json

3) Análisis Jurídico del Monitoreo (México)

El monitoreo de tráfico en una red privada perteneciente a una organización puede ser legal siempre que:
- Se informe y acepte por parte de los empleados en la política de uso de recursos informáticos de la empresa.
- El monitoreo se limite a lo necesario para la seguridad y se preserve la mínima intrusión. Evitar inspección profunda de contenido salvo que existan políticas y consentimientos explícitos.

Ley aplicable y consideraciones:
- La Ley Federal de Protección de Datos Personales en Posesión de los Particulares (LFPDPPP) puede aplicar si los registros contienen datos personales identificables (IPs pueden considerarse datos personales indirectos). Debe documentarse la base legal del tratamiento y las medidas de seguridad.
- Se recomienda elaborar una "Política de Monitoreo y Tratamiento de Datos" que establezca: finalidad, bases legales, responsables, medidas de seguridad, plazo de conservación y derechos ARCO.

Modelo de cláusula para póliza interna (resumen):
"La empresa podrá monitorear el tráfico de la red y registrar eventos con la finalidad de proteger la infraestructura y los datos. Los registros serán conservados por X días, y solo personal autorizado tendrá acceso."
