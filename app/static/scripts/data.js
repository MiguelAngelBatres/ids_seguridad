/* =========================================================
   IDS Console — sample data + i18n
   Deterministic generators so the mockup looks realistic
   while staying compact. Mirrors the real Flask data shapes.
========================================================= */
(function () {
  // ---- seeded RNG (mulberry32) ------------------------------------
  function rng(seed) {
    let a = seed >>> 0;
    return function () {
      a |= 0; a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  const pick = (r, arr) => arr[Math.floor(r() * arr.length)];
  const irand = (r, a, b) => a + Math.floor(r() * (b - a + 1));

  // anchor "now" — the data ends around this fictional time
  const NOW = 1780600000;

  // ---- shared pools ----------------------------------------------
  const LOCAL_MACS = ['c4:d0:e3:70:6d:40', '04:d5:90:0a:18:4c', 'a0:88:b4:1f:2c:e1'];
  const ATTACKER_IPS = ['192.0.2.10', '198.51.100.23', '45.155.205.118', '185.220.101.7', '141.98.10.62'];
  const LOCAL_IPS = ['10.13.140.32', '10.13.144.32', '192.168.1.39', '10.13.140.51'];
  const EXT_IPS = ['34.107.221.82', '203.0.113.66', '142.250.78.14', '20.42.65.92', '104.18.32.7'];
  const DNS_SRV = '148.211.120.54';
  const PROTOCOLS = ['TCP', 'HTTP', 'DNS', 'ICMP', 'UDP'];
  const DOMAINS = [
    'api.github.com', 'detectportal.firefox.com', 'mobile.events.data.microsoft.com',
    'main.vscode-cdn.net', 'incoming.telemetry.mozilla.org', 'default.exp-tas.com',
    'data-ai.microsoft.com', 'clients.google.com', null, null, null,
  ];
  const FLAGS = ['S', 'SA', 'A', 'AP', 'FA', 'R'];
  const PORTS = [80, 443, 53, 22, 3389, 3306, 8080, 23, 445, 5900, 21, 25];

  // ---- network reports (benign-ish traffic) ----------------------
  function genReports(n) {
    const r = rng(20260605);
    const out = [];
    let ts = NOW - n * 2;
    for (let i = 0; i < n; i++) {
      ts += irand(r, 0, 3);
      const outbound = r() > 0.5;
      const local = pick(r, LOCAL_IPS);
      const ext = r() > 0.25 ? pick(r, EXT_IPS) : DNS_SRV;
      const proto = pick(r, PROTOCOLS);
      const domain = proto === 'DNS' || proto === 'HTTP' ? pick(r, DOMAINS) : null;
      out.push({
        timestamp: ts,
        src_ip: outbound ? local : ext,
        src_mac: pick(r, LOCAL_MACS),
        src_port: proto === 'DNS' ? (outbound ? irand(r, 1024, 65500) : 53) : irand(r, 1024, 65500),
        dst: outbound ? ext : local,
        dst_port: proto === 'DNS' ? 53 : pick(r, PORTS),
        dst_mac: pick(r, LOCAL_MACS),
        domain: domain,
        protocol: proto,
        tcp_flags: proto === 'TCP' || proto === 'HTTP' ? pick(r, FLAGS) : null,
        size: irand(r, 60, 1480),
      });
    }
    return out;
  }

  // ---- alerts (the threats) --------------------------------------
  const HEUR = [
    { subtype: 'port_scan', risk: 'Posible escaneo de puertos', riskEn: 'Possible port scan', sev: 'medium' },
    { subtype: 'syn_flood', risk: 'Posible SYN flood', riskEn: 'Possible SYN flood', sev: 'high' },
    { subtype: 'icmp_flood', risk: 'Posible inundación ICMP', riskEn: 'Possible ICMP flood', sev: 'medium' },
    { subtype: 'brute_force', risk: 'Fuerza bruta a puertos sensibles', riskEn: 'Brute force on sensitive ports', sev: 'high' },
  ];

  function genAlerts(n) {
    const r = rng(773311);
    const out = [];
    let ts = NOW - n * 70;
    for (let i = 0; i < n; i++) {
      ts += irand(r, 30, 140);
      const roll = r();
      const src = pick(r, ATTACKER_IPS);
      const mac = pick(r, LOCAL_MACS);
      if (roll < 0.5) {
        // threat_intel — known-bad destination
        out.push({
          timestamp: ts, type: 'threat_intel', severity: 'critical',
          src_ip: src, src_mac: mac, src_port: irand(r, 1024, 65500),
          dst: '203.0.113.66', dst_port: pick(r, PORTS),
          domain: r() > 0.5 ? 'malicious.example' : null,
          protocol: pick(r, ['HTTP', 'TCP', 'DNS']),
          risk: 'Virus/Botnet', riskEn: 'Virus/Botnet',
          blacklist_note: 'Coincidencia con lista negra',
          evidence: { match: 'blacklist', list: 'abuse.ch/feodo', confidence: irand(r, 85, 99) + '%' },
        });
      } else if (roll < 0.68) {
        // arp_spoof
        const exp = pick(r, LOCAL_MACS);
        let act = pick(r, LOCAL_MACS); if (act === exp) act = 'de:ad:be:ef:00:' + irand(r, 10, 99);
        out.push({
          timestamp: ts, type: 'arp_spoof', severity: 'high',
          src_ip: pick(r, LOCAL_IPS), src_mac: act,
          dst: '192.168.1.1', dst_port: null, domain: null, protocol: 'ARP',
          risk: 'Suplantación ARP en la LAN', riskEn: 'ARP spoofing on the LAN',
          expected_mac: exp, actual_mac: act,
          evidence: { gateway: '192.168.1.1', expected_mac: exp, observed_mac: act },
        });
      } else {
        // heuristic
        const h = pick(r, HEUR);
        const ports = Array.from({ length: irand(r, 6, 18) }, () => pick(r, PORTS));
        out.push({
          timestamp: ts, type: 'heuristic', subtype: h.subtype, severity: h.sev,
          src_ip: src, src_mac: mac, src_port: irand(r, 1024, 65500),
          dst: pick(r, LOCAL_IPS), dst_port: pick(r, PORTS),
          protocol: h.subtype === 'icmp_flood' ? 'ICMP' : 'TCP',
          risk: h.risk, riskEn: h.riskEn,
          evidence: h.subtype === 'port_scan'
            ? { unique_ports: ports.length, sample_ports: [...new Set(ports)].sort((a, b) => a - b), window_seconds: 60 }
            : { packets: irand(r, 50, 320), window_seconds: irand(r, 10, 60) },
        });
      }
    }
    return out;
  }

  const reports = genReports(220);
  const alerts = genAlerts(46);

  const whitelist = [
    { key: 'auto-1780498526', ip: '10.13.140.32', mac: 'c4:d0:e3:70:6d:40', note: 'Host local' },
    { key: '10.13.144.32--1780498900', ip: '10.13.144.32', mac: null, note: 'Mi computadora' },
    { key: '192.168.1.39--1780498900', ip: '192.168.1.39', mac: null, note: 'Mi computadora en la casa' },
    { key: '192.168.1.1--1780550197', ip: '192.168.1.1', mac: null, note: 'Router/gateway de la casa' },
  ];

  // ---- i18n -------------------------------------------------------
  const I18N = {
    es: {
      brand_sub: 'Sistema de Detección de Intrusos',
      nav_overview: 'Resumen', nav_alerts: 'Alertas', nav_reports: 'Reportes', nav_whitelist: 'Lista Blanca',
      monitor_on: 'Monitor activo', monitor_iface: 'simulación', live: 'En vivo', updated: 'actualizado',
      search: 'Buscar…', clear_alerts: 'Limpiar alertas', clear_reports: 'Limpiar reportes',
      all: 'Todas', none_alerts: 'Sin alertas registradas.', none_reports: 'Sin reportes registrados.',
      // overview
      ov_title: 'Resumen del sistema', ov_sub: 'Estado de la red en tiempo real',
      kpi_alerts: 'Alertas totales', kpi_events: 'Eventos capturados', kpi_sources: 'IPs origen únicas', kpi_threats: 'Amenazas críticas',
      last24: 'últimas 24 h', vs_prev: 'vs. periodo previo',
      chart_timeline: 'Alertas en el tiempo', chart_types: 'Por tipo de alerta', chart_proto: 'Por protocolo',
      chart_risk: 'Distribución de riesgo', chart_top: 'Top IPs de origen', feed_title: 'Actividad reciente',
      // table headers
      h_time: 'Hora', h_type: 'Tipo', h_src: 'Origen', h_dst: 'Destino', h_proto: 'Protocolo',
      h_risk: 'Riesgo', h_evidence: 'Evidencia', h_domain: 'Dominio', h_size: 'Tamaño', h_sev: 'Severidad',
      view: 'ver', hide: 'ocultar', events_captured: 'eventos capturados', alerts_detected: 'alertas detectadas',
      // severity
      sev_critical: 'Crítica', sev_high: 'Alta', sev_medium: 'Media', sev_low: 'Baja',
      // whitelist
      wl_title: 'Lista Blanca', wl_sub: 'IPs y MACs de confianza, ignoradas por el monitor',
      wl_add: 'Agregar entrada', wl_ip: 'Dirección IP', wl_mac: 'Dirección MAC', wl_note: 'Nota',
      wl_optional: 'opcional', wl_submit: 'Agregar a la lista', wl_entries: 'Entradas de confianza',
      wl_remove: 'Eliminar', wl_empty: 'Aún no hay entradas en la lista blanca.', wl_count: 'entradas',
      expected: 'esperada', observed: 'observada', ago: 'hace',
    },
    en: {
      brand_sub: 'Intrusion Detection System',
      nav_overview: 'Overview', nav_alerts: 'Alerts', nav_reports: 'Reports', nav_whitelist: 'Whitelist',
      monitor_on: 'Monitor active', monitor_iface: 'simulation', live: 'Live', updated: 'updated',
      search: 'Search…', clear_alerts: 'Clear alerts', clear_reports: 'Clear reports',
      all: 'All', none_alerts: 'No alerts recorded.', none_reports: 'No reports recorded.',
      ov_title: 'System overview', ov_sub: 'Real-time network status',
      kpi_alerts: 'Total alerts', kpi_events: 'Captured events', kpi_sources: 'Unique source IPs', kpi_threats: 'Critical threats',
      last24: 'last 24 h', vs_prev: 'vs. prev. period',
      chart_timeline: 'Alerts over time', chart_types: 'By alert type', chart_proto: 'By protocol',
      chart_risk: 'Risk distribution', chart_top: 'Top source IPs', feed_title: 'Recent activity',
      h_time: 'Time', h_type: 'Type', h_src: 'Source', h_dst: 'Destination', h_proto: 'Protocol',
      h_risk: 'Risk', h_evidence: 'Evidence', h_domain: 'Domain', h_size: 'Size', h_sev: 'Severity',
      view: 'view', hide: 'hide', events_captured: 'events captured', alerts_detected: 'alerts detected',
      sev_critical: 'Critical', sev_high: 'High', sev_medium: 'Medium', sev_low: 'Low',
      wl_title: 'Whitelist', wl_sub: 'Trusted IPs and MACs, ignored by the monitor',
      wl_add: 'Add entry', wl_ip: 'IP address', wl_mac: 'MAC address', wl_note: 'Note',
      wl_optional: 'optional', wl_submit: 'Add to list', wl_entries: 'Trusted entries',
      wl_remove: 'Remove', wl_empty: 'No whitelist entries yet.', wl_count: 'entries',
      expected: 'expected', observed: 'observed', ago: '',
    },
  };

  window.IDS_DATA = { reports, alerts, whitelist, I18N, NOW };
})();
