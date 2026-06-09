/* =========================================================
   IDS Console — live application
   Polls /api/alerts and /api/reports every 3s for live data.
   Falls back to static mock data if server data unavailable.
========================================================= */
const { useState, useEffect, useMemo, useRef } = React;
const D = window.IDS_DATA || {};
const INIT = window.__INITIAL_DATA__ || { reports: [], alerts: [], whitelist: [] };

const I18N = D.I18N || {};

/* ---------- helpers ---------- */
const SEV = {
  critical: { c: '#ff5a5f', key: 'Alerta crítica' },
  high: { c: '#c084fc', key: 'Alta' },
  medium: { c: '#fbbf24', key: 'Media' },
  low: { c: '#38bdf8', key: 'Baja' },
};
const PROTO_COLOR = {
  TCP: '#3ddc97', HTTP: '#38bdf8', DNS: '#fbbf24', ICMP: '#c084fc', UDP: '#64748b', ARP: '#ff5a5f',
};
const pad = (n) => String(n).padStart(2, '0');
function fmtTime(ts) {
  const d = new Date(ts * 1000);
  return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
}
function fmtClock(d) {
  return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
}
function timeAgo(ts, now, lang) {
  let s = Math.max(0, now - ts);
  const m = Math.floor(s / 60), h = Math.floor(m / 60);
  if (lang === 'es') {
    if (h > 0) return `hace ${h} h`;
    if (m > 0) return `hace ${m} min`;
    return `hace ${s} s`;
  }
  if (h > 0) return `${h} h ago`;
  if (m > 0) return `${m} min ago`;
  return `${s} s ago`;
}
function alertSeverity(a) { return a.severity || (a.type === 'threat_intel' ? 'critical' : a.type === 'arp_spoof' ? 'high' : 'medium'); }
function alertLabel(a) { return a.type === 'heuristic' ? (a.subtype || 'heuristic') : a.type; }

function wiresharkFilter(r) {
  const parts = [];
  if (r.src_ip && r.dst) parts.push(`ip.addr == ${r.src_ip} && ip.addr == ${r.dst}`);
  else if (r.src_ip) parts.push(`ip.addr == ${r.src_ip}`);
  else if (r.dst) parts.push(`ip.addr == ${r.dst}`);
  const proto = (r.protocol || '').toUpperCase();
  if (proto === 'TCP' || proto === 'HTTP') {
    if (r.dst_port) parts.push(`tcp.port == ${r.dst_port}`);
  } else if (proto === 'UDP') {
    if (r.dst_port) parts.push(`udp.port == ${r.dst_port}`);
  } else if (proto === 'DNS') {
    parts.push('dns');
    if (r.domain) parts.push(`dns.qry.name == "${r.domain}"`);
  } else if (proto === 'ICMP') {
    parts.push('icmp');
  } else if (proto === 'ARP') {
    parts.push('arp');
    if (r.src_ip) parts.push(`arp.src.proto_ipv4 == ${r.src_ip}`);
  } else if (proto === 'IGMP') {
    parts.push('igmp');
  }
  if (r.src_mac) parts.push(`eth.addr == ${r.src_mac}`);
  return parts.join(' && ') || 'ip';
}

function CopyWsBtn({ r }) {
  const [copied, setCopied] = useState(false);
  const f = wiresharkFilter(r);
  const copy = () => {
    navigator.clipboard.writeText(f).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <button className="ws-btn" title={f} onClick={copy}>
      {copied ? '✓' : '🦈'}
    </button>
  );
}

/* ---------- small UI atoms ---------- */
function TypeBadge({ a }) {
  const sev = alertSeverity(a);
  const color = SEV[sev].c;
  return (
    <span className="type-badge" style={{ color, borderColor: color + '55', background: color + '14' }}>
      <span className="tb-dot" style={{ background: color }}></span>
      {alertLabel(a)}
    </span>
  );
}
function ProtoChip({ p }) {
  const c = PROTO_COLOR[p] || '#64748b';
  return <span className="proto-chip" style={{ color: c, borderColor: c + '44' }}>{p || '—'}</span>;
}
function Live({ t, ts }) {
  return (
    <span className="live">
      <span className="live-dot"></span>
      <span className="live-txt">{t('live')}</span>
      <span className="live-ts mono">{ts}</span>
    </span>
  );
}

/* ============================================================
   OVERVIEW
============================================================ */
function Overview({ t, lang, now, data }) {
  const { alerts, reports } = data;

  const agg = useMemo(() => {
    const srcCount = {}, typeCount = { unauthorized_device: 0, threat_intel: 0, arp_spoof: 0, heuristic: 0 };
    const sevCount = { critical: 0, high: 0, medium: 0, low: 0 };
    alerts.forEach((a) => {
      srcCount[a.src_ip] = (srcCount[a.src_ip] || 0) + 1;
      typeCount[a.type] = (typeCount[a.type] || 0) + 1;
      sevCount[alertSeverity(a)]++;
    });
    const protoCount = {};
    reports.forEach((r) => { protoCount[r.protocol] = (protoCount[r.protocol] || 0) + 1; });

    const ts = alerts.map((a) => a.timestamp);
    const min = ts.length ? Math.min(...ts) : now - 3600;
    const max = ts.length ? Math.max(...ts) : now;
    const N = 12, span = (max - min) / N || 1;
    const buckets = new Array(N).fill(0), blabels = [];
    alerts.forEach((a) => { const i = Math.min(N - 1, Math.floor((a.timestamp - min) / span)); buckets[i]++; });
    for (let i = 0; i < N; i++) blabels.push(fmtTime(min + i * span).slice(0, 5));

    const topSrc = Object.entries(srcCount).sort((a, b) => b[1] - a[1]).slice(0, 5)
      .map(([label, value]) => ({ label, value, color: '#ff5a5f' }));
    const topProto = Object.entries(protoCount).sort((a, b) => b[1] - a[1])
      .map(([label, value]) => ({ label, value, color: PROTO_COLOR[label] || '#3ddc97' }));

    return { srcCount, typeCount, sevCount, protoCount, buckets, blabels, topSrc, topProto };
  }, [alerts, reports]);

  const uniqueSrc = Object.keys(agg.srcCount).length;
  const kpis = [
    { key: 'Alertas totales', val: alerts.length, sub: 'alertas detectadas', color: '#3ddc97', spark: agg.buckets },
    { key: 'Eventos capturados', val: reports.length, sub: 'eventos capturados', color: '#38bdf8', spark: [4, 8, 6, 12, 9, 14, 11, 18] },
    { key: 'IPs origen únicas', val: uniqueSrc, sub: 'últimas 24 h', color: '#c084fc', spark: [2, 3, 3, 4, 5, 5] },
    { key: 'Amenazas críticas', val: agg.sevCount.critical, sub: 'últimas 24 h', color: '#ff5a5f', spark: [1, 2, 1, 3, 4, 3, 5] },
  ];

  const typeSlices = [
    { label: 'threat_intel', value: agg.typeCount.threat_intel, color: '#ff5a5f' },
    { label: 'arp_spoof', value: agg.typeCount.arp_spoof, color: '#c084fc' },
    { label: 'heuristic', value: agg.typeCount.heuristic, color: '#fbbf24' },
  ];
  const riskSlices = ['critical', 'high', 'medium', 'low']
    .map((k) => ({ label: SEV[k].key, value: agg.sevCount[k], color: SEV[k].c }))
    .filter((s) => s.value > 0);

  const feed = [...alerts].slice(-7).reverse();

  return (
    <div className="screen">
      <div className="kpi-row">
        {kpis.map((k) => (
          <div className="kpi-card" key={k.key}>
            <div className="kpi-top">
              <span className="kpi-label">{k.key}</span>
            </div>
            <div className="kpi-val mono" style={{ color: k.color }}>{k.val}</div>
            <div className="kpi-sub">{k.sub}</div>
          </div>
        ))}
      </div>

      <div className="grid-2">
        <section className="card span-2-wide">
          <div className="card-head"><h3>Alertas en el tiempo</h3><span className="card-tag mono">{alerts.length} total</span></div>
          {agg.buckets.length > 0 ? (
             <div className="chart-wrap" style={{ height: '220px', marginTop: '12px' }}>
               <AreaTimeline series={agg.buckets} labels={agg.blabels} height={220} color="#3ddc97" />
             </div>
          ) : (
            <div className="empty small">No hay suficientes datos de alertas</div>
          )}
        </section>
        <section className="card">
          <div className="card-head"><h3>Distribución de riesgo</h3></div>
          {riskSlices.length ? (
            <ul className="legend">
              {riskSlices.map((s) => (
                <li key={s.label}>
                  <span className="dot" style={{ background: s.color }}></span>
                  <span className="lg-label">{s.label}</span>
                  <span className="lg-val">{s.value}</span>
                </li>
              ))}
            </ul>
          ) : (
            <div className="empty small">Sin alertas de riesgo aún</div>
          )}
        </section>
      </div>

      <section className="card">
        <div className="card-head"><h3>Actividad reciente</h3><Live t={t} ts="" /></div>
        <ul className="feed">
          {feed.map((a, i) => (
            <li key={i} className="feed-row">
              <span className="feed-bar" style={{ background: SEV[alertSeverity(a)].c }}></span>
              <span className="feed-time mono">{fmtTime(a.timestamp)}</span>
              <TypeBadge a={a} />
              <span className="feed-src mono">{a.src_ip}</span>
              <span className="feed-arrow">→</span>
              <span className="feed-dst mono">{a.dst}{a.dst_port ? ':' + a.dst_port : ''}</span>
              <span className="feed-risk">{a.risk}</span>
              <span className="feed-ago">{timeAgo(a.timestamp, now, lang)}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

/* ============================================================
   ALERTS
============================================================ */
function Alerts({ t, lang, liveTs, data, onClear }) {
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState('all');
  const [open, setOpen] = useState({});

  function quickWhitelist(ip, mac) {
    if (!confirm(`¿Agregar ${ip || mac} a la lista blanca?`)) return;
    fetch('/api/whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, mac, note: 'Agregado desde Alertas' }),
    }).then(r => r.json()).then(d => {
      if (d.ok) {
        alert('Agregado a lista blanca exitosamente.');
      } else {
        alert('Error: ' + d.error);
      }
    });
  }

  const alerts = data.alerts;
  const rows = useMemo(() => [...alerts].reverse(), [alerts]);
  const types = ['all', 'unauthorized_device', 'threat_intel', 'arp_spoof', 'heuristic'];
  const counts = useMemo(() => {
    const c = { all: rows.length, unauthorized_device: 0, threat_intel: 0, arp_spoof: 0, heuristic: 0 };
    rows.forEach((a) => { c[a.type]++; });
    return c;
  }, [rows]);

  const shown = rows.filter((a) => {
    if (filter !== 'all' && a.type !== filter) return false;
    if (!q) return true;
    const hay = [a.src_ip, a.src_mac, a.dst, a.domain, a.protocol, a.risk, alertLabel(a)].join(' ').toLowerCase();
    return hay.includes(q.toLowerCase());
  });

  return (
    <div className="screen">
      <div className="toolbar">
        <div className="chips">
          {types.map((ty) => (
            <button key={ty} className={'chip' + (filter === ty ? ' active' : '')} onClick={() => setFilter(ty)}>
              {ty === 'all' ? 'Todas' : ty}<span className="chip-n">{counts[ty]}</span>
            </button>
          ))}
        </div>
        <div className="toolbar-right">
          <div className="search"><span className="search-i">⌕</span>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Buscar…" />
          </div>
          <Live t={t} ts={liveTs} />
          <button className="btn-danger" onClick={() => { 
            const msg = filter === 'all' ? '¿Limpiar todas las alertas?' : `¿Limpiar alertas de tipo ${filter}?`;
            if (confirm(msg)) onClear(filter); 
          }}>
            Limpiar alertas
          </button>
        </div>
      </div>

      {shown.length ? (
        <div className="table-card">
          <table className="data-table">
            <thead>
              <tr>
                <th className="w-time">Hora</th><th>Tipo</th><th>Origen</th>
                <th>Destino</th><th>Proto</th><th>Riesgo</th><th className="w-ev">Evidencia</th><th className="w-ws">Wireshark</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((a, i) => {
                const sev = alertSeverity(a);
                return (
                  <React.Fragment key={a.timestamp + '-' + i}>
                    <tr className="data-row" style={{ '--sev': SEV[sev].c }}>
                      <td className="mono nowrap">{fmtTime(a.timestamp)}</td>
                      <td><TypeBadge a={a} /></td>
                      <td className="mono">
                        <div>{a.src_ip || 'N/D'}</div>
                        <div className="sub">
                          {a.src_mac || ''}
                          {a.type === 'unauthorized_device' && (
                            <button 
                              className="btn-tiny" 
                              style={{ marginLeft: '8px', padding: '1px 6px', fontSize: '10px', background: '#3ddc97', color: '#0a0e12', border: 'none', borderRadius: '3px', cursor: 'pointer' }}
                              onClick={() => quickWhitelist(a.src_ip, a.src_mac)}
                              title="Agregar IP/MAC a la Lista Blanca"
                            >
                              + WL
                            </button>
                          )}
                        </div>
                      </td>
                      <td className="mono"><div>{(a.dst || 'N/D') + (a.dst_port ? ':' + a.dst_port : '')}</div><div className="sub">{a.domain || ''}</div></td>
                      <td><ProtoChip p={a.protocol} /></td>
                      <td className="risk-cell">{a.risk}</td>
                      <td>
                        {a.evidence ? (
                          <button className="ev-btn" onClick={() => setOpen((o) => ({ ...o, [i]: !o[i] }))}>
                            {open[i] ? 'ocultar' : 'ver'}
                          </button>
                        ) : <span className="sub">—</span>}
                      </td>
                      <td className="ws-cell"><CopyWsBtn r={a} /></td>
                    </tr>
                    {open[i] && a.evidence && (
                      <tr className="ev-row"><td colSpan="8">
                        <div className="ev-box">
                          {a.type === 'arp_spoof' && (
                            <div className="ev-line"><span className="ev-k">esperada</span><span className="mono">{a.expected_mac}</span>
                              <span className="ev-k">observada</span><span className="mono warn">{a.actual_mac}</span></div>
                          )}
                          <pre className="mono">{JSON.stringify(a.evidence, null, 2)}</pre>
                        </div>
                      </td></tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty">Sin alertas registradas.</div>
      )}
    </div>
  );
}

/* ============================================================
   REPORTS
============================================================ */
function Reports({ t, lang, liveTs, data, onClear }) {
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState('all');

  const reports = data.reports;
  const rows = useMemo(() => [...reports].reverse(), [reports]);
  const protos = ['all', ...Array.from(new Set(reports.map((r) => r.protocol)))];

  const shown = rows.filter((r) => {
    if (filter !== 'all' && r.protocol !== filter) return false;
    if (!q) return true;
    const hay = [r.src_ip, r.dst, r.domain, r.protocol, r.tcp_flags].join(' ').toLowerCase();
    return hay.includes(q.toLowerCase());
  });

  return (
    <div className="screen">
      <div className="toolbar">
        <div className="chips">
          {protos.map((p) => (
            <button key={p} className={'chip' + (filter === p ? ' active' : '')} onClick={() => setFilter(p)}>
              {p === 'all' ? 'Todas' : p}
            </button>
          ))}
        </div>
        <div className="toolbar-right">
          <span className="count-pill mono">{shown.length} eventos capturados</span>
          <div className="search"><span className="search-i">⌕</span>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Buscar…" />
          </div>
          <Live t={t} ts={liveTs} />
          <button className="btn-danger" onClick={() => { 
            const msg = filter === 'all' ? '¿Limpiar todos los reportes?' : `¿Limpiar reportes de protocolo ${filter}?`;
            if (confirm(msg)) onClear(filter); 
          }}>
            Limpiar reportes
          </button>
        </div>
      </div>

      {shown.length ? (
        <div className="table-card">
          <table className="data-table">
            <thead>
              <tr>
                <th className="w-time">Hora</th><th>Origen</th><th>Destino</th>
                <th>Proto</th><th>Dominio</th><th className="w-size">Tamaño</th><th className="w-ws">Wireshark</th>
              </tr>
            </thead>
            <tbody>
              {shown.slice(0, 400).map((r, i) => (
                <tr className="data-row plain" key={r.timestamp + '-' + i}>
                  <td className="mono nowrap">{fmtTime(r.timestamp)}</td>
                  <td className="mono"><div>{(r.src_ip || 'N/D') + (r.src_port ? ':' + r.src_port : '')}</div><div className="sub">{r.src_mac || ''}</div></td>
                  <td className="mono"><div>{(r.dst || 'N/D') + (r.dst_port ? ':' + r.dst_port : '')}</div><div className="sub">{r.dst_mac || ''}</div></td>
                  <td><ProtoChip p={r.protocol} />{r.tcp_flags ? <span className="flags mono">{r.tcp_flags}</span> : null}</td>
                  <td className="mono dim">{r.domain || ''}</td>
                  <td className="mono nowrap">{r.size != null ? r.size + ' B' : ''}</td>
                  <td className="ws-cell"><CopyWsBtn r={r} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty">Sin reportes registrados.</div>
      )}
    </div>
  );
}
/* ============================================================
   WHITELIST
============================================================ */
function Whitelist({ t, lang }) {
    const [entries, setEntries] = useState([]);
    const [msg, setMsg] = useState('');
    const ipRef = useRef(null);
    const macRef = useRef(null);
    const noteRef = useRef(null);

    function fetchWhitelist() {
      fetch('/api/whitelist')
        .then(r => r.json())
        .then(d => { if (d.whitelist) setEntries(d.whitelist); })
        .catch(() => { });
    }

    useEffect(() => { fetchWhitelist(); }, []);

    function addEntry(e) {
      e.preventDefault();
      const ip = ipRef.current ? ipRef.current.value.trim() : '';
      const mac = macRef.current ? macRef.current.value.trim() : '';
      const note = noteRef.current ? noteRef.current.value.trim() : '';
      if (!ip && !mac) return;
      fetch('/api/whitelist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, mac, note }),
      })
        .then(r => r.json())
        .then(d => {
          if (d.ok) {
            if (ipRef.current) ipRef.current.value = '';
            if (macRef.current) macRef.current.value = '';
            if (noteRef.current) noteRef.current.value = '';
            setMsg('');
            fetchWhitelist();
          } else {
            setMsg(d.error || 'Error');
          }
        })
        .catch(() => setMsg('Error de conexión'));
    }

    function removeEntry(key) {
      fetch('/api/whitelist/remove', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key }),
      })
        .then(r => r.json())
        .then(d => { if (d.ok) fetchWhitelist(); })
        .catch(() => { });
    }

    return (
      <div className="screen wl-screen">
        <div className="wl-grid">
          <section className="card wl-form-card">
            <div className="card-head"><h3>Agregar entrada</h3></div>
            {msg && <div className="flash-err">{msg}</div>}
            <form onSubmit={addEntry} className="wl-form">
              <label className="field">
                <span className="field-l">Dirección IP</span>
                <input ref={ipRef} className="mono" name="ip" placeholder="192.168.1.50" />
              </label>
              <label className="field">
                <span className="field-l">Dirección MAC <em>opcional</em></span>
                <input ref={macRef} className="mono" name="mac" placeholder="aa:bb:cc:dd:ee:ff" />
              </label>
              <label className="field">
                <span className="field-l">Nota</span>
                <input ref={noteRef} name="note" placeholder="Ej. Impresora de oficina" />
              </label>
              <button type="submit" className="btn-primary">Agregar a la lista</button>
            </form>
          </section>

          <section className="card wl-list-card">
            <div className="card-head"><h3>Entradas de confianza</h3><span className="card-tag mono">{entries.length} entradas</span></div>
            {entries.length ? (
              <ul className="wl-list">
                {entries.map((e) => (
                  <li key={e.key} className="wl-item">
                    <span className="wl-avatar mono">{(e.ip || e.mac || '?').slice(0, 2)}</span>
                    <div className="wl-meta">
                      <div className="wl-ids mono">
                        {e.ip && <span className="wl-ip">{e.ip}</span>}
                        {e.mac && <span className="wl-mac">{e.mac}</span>}
                      </div>
                      {e.note && <div className="wl-note">{e.note}</div>}
                    </div>
                    <button className="wl-del" title="Eliminar" onClick={() => removeEntry(e.key)}>✕</button>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="empty small">No hay entradas autorizadas.</div>
            )}
          </section>
        </div>
      </div>
    );
  }

  /* ============================================================
     APP SHELL
  ============================================================ */
  const NAV = [
    { id: 'overview', icon: '◉', key: 'Resumen' },
    { id: 'alerts', icon: '⚠', key: 'Alertas' },
    { id: 'reports', icon: '≣', key: 'Reportes' },
    { id: 'whitelist', icon: '✓', key: 'Lista Blanca' },
  ];

  function App() {
    const [lang, setLang] = useState(() => localStorage.getItem('ids_lang') || 'es');
    const [screen, setScreen] = useState(() => localStorage.getItem('ids_screen') || 'overview');
    const [clock, setClock] = useState(new Date());
    const [now, setNow] = useState(Math.floor(Date.now() / 1000));

    const [reports, setReports] = useState(INIT.reports);
    const [alerts, setAlerts] = useState(INIT.alerts);
    const [whitelist, setWhitelist] = useState(INIT.whitelist);

    const lastAlertTs = useRef(
      INIT.alerts.reduce((max, a) => Math.max(max, a.timestamp || 0), 0)
    );
    const lastReportTs = useRef(
      INIT.reports.reduce((max, r) => Math.max(max, r.timestamp || 0), 0)
    );

    const t = (k) => k;

    useEffect(() => { localStorage.setItem('ids_lang', lang); }, [lang]);
    useEffect(() => { localStorage.setItem('ids_screen', screen); }, [screen]);

    // Poll alerts
    useEffect(() => {
      const id = setInterval(async () => {
        try {
          const r = await fetch(`/api/alerts?since=${lastAlertTs.current}`);
          const data = await r.json();
          if (data.alerts && data.alerts.length) {
            setAlerts(prev => [...prev, ...data.alerts]);
            const maxTs = data.alerts.reduce((m, a) => Math.max(m, a.timestamp || 0), lastAlertTs.current);
            lastAlertTs.current = maxTs;
          }
        } catch (e) { }
      }, 3000);
      return () => clearInterval(id);
    }, []);

    // Poll reports
    useEffect(() => {
      const id = setInterval(async () => {
        try {
          const r = await fetch(`/api/reports?since=${lastReportTs.current}`);
          const data = await r.json();
          if (data.reports && data.reports.length) {
            setReports(prev => [...prev, ...data.reports]);
            const maxTs = data.reports.reduce((m, r) => Math.max(m, r.timestamp || 0), lastReportTs.current);
            lastReportTs.current = maxTs;
          }
        } catch (e) { }
      }, 3000);
      return () => clearInterval(id);
    }, []);

    // Poll whitelist for sidebar updates
    useEffect(() => {
      const id = setInterval(() => {
        fetch('/api/whitelist')
          .then(r => r.json())
          .then(d => { if (d.whitelist) setWhitelist(d.whitelist); })
          .catch(() => { });
      }, 5000);
      return () => clearInterval(id);
    }, []);

    // Update clock
    useEffect(() => {
      const id = setInterval(() => { setClock(new Date()); setNow((n) => n + 3); }, 3000);
      return () => clearInterval(id);
    }, []);

    useEffect(() => {
      const id = setInterval(() => {
        fetch('/api/reports')
          .then(r => r.json())
          .then(data => {
            if (data.reports) {
              setReports(data.reports);
              const maxTs = data.reports.reduce((m, r) => Math.max(m, r.timestamp || 0), 0);
              lastReportTs.current = maxTs;
            }
          })
          .catch(() => { });
      }, 10000);
      return () => clearInterval(id);
    }, []);

    useEffect(() => {
      const id = setInterval(() => {
        fetch('/api/alerts')
          .then(r => r.json())
          .then(data => {
            if (data.alerts) {
              setAlerts(data.alerts);
              const maxTs = data.alerts.reduce((m, a) => Math.max(m, a.timestamp || 0), 0);
              lastAlertTs.current = maxTs;
            }
          })
          .catch(() => { });
      }, 10000);
      return () => clearInterval(id);
    }, []);

    const liveTs = '· ' + fmtClock(clock);
    const data = { reports, alerts, whitelist };

    function clearAlerts(typeFilter) {
      fetch('/api/alerts/clear', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: typeFilter === 'all' ? null : typeFilter })
      })
        .then(() => {
          if (typeFilter === 'all') {
            setAlerts([]);
          } else {
            setAlerts(prev => prev.filter(a => a.type !== typeFilter));
          }
          lastAlertTs.current = Math.floor(Date.now() / 1000);
        })
        .catch(() => { });
    }

    function clearReports(protoFilter) {
      fetch('/api/reports/clear', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ protocol: protoFilter === 'all' ? null : protoFilter })
      })
        .then(() => {
          if (protoFilter === 'all') {
            setReports([]);
          } else {
            setReports(prev => prev.filter(r => r.protocol !== protoFilter));
          }
          lastReportTs.current = Math.floor(Date.now() / 1000);
        })
        .catch(() => { });
    }

    return (
      <div className="app">
        <aside className="sidebar">
          <div className="brand">
            <div className="brand-mark mono">IDS<span className="blink">_</span></div>
            <div className="brand-sub">Sistema de Detección de Intrusos</div>
          </div>
          <nav className="nav">
            {NAV.map((n) => (
              <button key={n.id} className={'nav-item' + (screen === n.id ? ' active' : '')} onClick={() => setScreen(n.id)}>
                <span className="nav-ic">{n.icon}</span>
                <span>{n.key}</span>
                {n.id === 'alerts' && <span className="nav-badge">{alerts.length}</span>}
              </button>
            ))}
          </nav>
          <div className="side-foot">
            <div className="monitor">
              <span className="mon-dot"></span>
              <div>
                <div className="mon-l">Monitor activo</div>
                <div className="mon-s mono">iface: simulación</div>
              </div>
            </div>
            <div className="lang-toggle">
              {['es', 'en'].map((l) => (
                <button key={l} className={'lang-btn' + (lang === l ? ' active' : '')} onClick={() => setLang(l)}>{l.toUpperCase()}</button>
              ))}
            </div>
          </div>
        </aside>

        <main className="main">
          <header className="topbar">
            <div className="topbar-l">
              <span className="prompt mono">~/ids<span className="prompt-sep">/</span>{screen}</span>
              <h1>{NAV.find((n) => n.id === screen).key}</h1>
            </div>
            <div className="topbar-r">
              <span className="sys-clock mono">{fmtClock(clock)}</span>
            </div>
          </header>
          <div className="content">
            {screen === 'overview' && <Overview t={t} lang={lang} now={now} data={data} />}
            {screen === 'alerts' && <Alerts t={t} lang={lang} liveTs={liveTs} data={data} onClear={clearAlerts} />}
            {screen === 'reports' && <Reports t={t} lang={lang} liveTs={liveTs} data={data} onClear={clearReports} />}
            {screen === 'whitelist' && <Whitelist />}
          </div>
        </main>
      </div>
    );
  }

  ReactDOM.createRoot(document.getElementById('root')).render(<App />);
