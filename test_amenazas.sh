#!/usr/bin/env bash
# ============================================================
#  test_amenazas.sh — Genera tráfico que dispara alertas
#  críticas en el IDS.
#
#  USO:  chmod +x test_amenazas.sh && ./test_amenazas.sh
#
#  El IDS debe estar corriendo en la misma red WiFi.
#  Este script se ejecuta desde OTRA máquina (la de tu amigo).
# ============================================================

set -e

# --- IP del IDS (cambiar si es diferente) ---
IDS_IP="10.13.60.199"

# --- IPs de la blacklist del IDS ---
# El IDS tiene estas IPs marcadas como peligrosas.
# Cualquier conexión hacia ellas dispara una alerta "threat_intel" (crítica).
BLACKLIST_IP1="45.33.32.156"    # scanme.nmap.org (IP pública de prueba de Nmap)
BLACKLIST_IP2="198.51.100.77"   # IP ficticia de ejemplo

echo "=========================================="
echo "  Script de prueba de amenazas para IDS"
echo "=========================================="
echo ""

# ----------------------------------------------------------
#  1) AMENAZA CRÍTICA: Conexión a IP en lista negra
#     Dispara: threat_intel + consulta Whois automática
# ----------------------------------------------------------
echo "[1/4] Generando conexiones a IP en lista negra (threat_intel)..."
echo "      Destino: $BLACKLIST_IP1 (scanme.nmap.org)"

# Intentar conectar por varios puertos a la IP blacklisteada
for port in 80 443 22 8080; do
    echo "  -> Conectando a $BLACKLIST_IP1:$port ..."
    timeout 2 bash -c "echo '' > /dev/tcp/$BLACKLIST_IP1/$port" 2>/dev/null || true
    sleep 0.3
done

# También hacer consultas DNS a un dominio en la blacklist
echo "  -> Consultando DNS de scanme.nmap.org ..."
nslookup scanme.nmap.org >/dev/null 2>&1 || true
dig scanme.nmap.org +short >/dev/null 2>&1 || true

echo "  ✓ Conexiones a IP peligrosa completadas"
echo ""

# ----------------------------------------------------------
#  2) HEURÍSTICA: Escaneo de puertos
#     Dispara: heuristic/port_scan
# ----------------------------------------------------------
echo "[2/4] Simulando escaneo de puertos hacia $IDS_IP (port_scan)..."

for port in $(seq 20 50); do
    timeout 0.3 bash -c "echo '' > /dev/tcp/$IDS_IP/$port" 2>/dev/null || true
done

echo "  ✓ Escaneo de 30 puertos completado"
echo ""

# ----------------------------------------------------------
#  3) HEURÍSTICA: Inundación ICMP
#     Dispara: heuristic/icmp_flood
# ----------------------------------------------------------
echo "[3/4] Generando inundación ICMP hacia $IDS_IP (icmp_flood)..."

ping -c 30 -i 0.1 -s 64 "$IDS_IP" >/dev/null 2>&1 || true

echo "  ✓ 30 pings ICMP enviados"
echo ""

# ----------------------------------------------------------
#  4) HEURÍSTICA: Fuerza bruta en puertos sensibles
#     Dispara: heuristic/brute_force
# ----------------------------------------------------------
echo "[4/4] Simulando fuerza bruta en puertos sensibles (brute_force)..."

for i in $(seq 1 25); do
    timeout 0.3 bash -c "echo '' > /dev/tcp/$IDS_IP/22" 2>/dev/null || true
    timeout 0.3 bash -c "echo '' > /dev/tcp/$IDS_IP/3389" 2>/dev/null || true
done

echo "  ✓ 50 intentos a puertos SSH/RDP completados"
echo ""

echo "=========================================="
echo "  ¡Listo! Revisa el IDS en:"
echo "  http://$IDS_IP:5000"
echo ""
echo "  Deberías ver alertas de:"
echo "    • threat_intel  (Amenaza crítica)"
echo "    • port_scan     (Heurística)"
echo "    • icmp_flood    (Heurística)"
echo "    • brute_force   (Heurística)"
echo "=========================================="
