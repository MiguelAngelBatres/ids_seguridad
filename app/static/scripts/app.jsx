/* =========================================================
   IDS Console — application
========================================================= */
const { useState, useEffect, useMemo, useRef } = React;
const D = window.IDS_DATA;

/* ---------- helpers ---------- */
const SEV = {
  critical: { c: '#ff5a5f', key: 'sev_critical' },
  high:     { c: '#c084fc', key: 'sev_high' },
  medium:   { c: '#fbbf24', key: 'sev_medium' },
  low:      { c: '#38bdf8', key: 'sev_low' },
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
function Overview({ t, lang, now }) {
  const { alerts, reports } = D;

  const agg = useMemo(() => {
    const srcCount = {}, typeCount = { threat_intel: 0, arp_spoof: 0, heuristic: 0 };
    const sevCount = { critical: 0, high: 0, medium: 0, low: 0 };
    alerts.forEach((a) => {
      srcCount[a.src_ip] = (srcCount[a.src_ip] || 0) + 1;
      typeCount[a.type] = (typeCount[a.type] || 0) + 1;
      sevCount[alertSeverity(a)]++;
    });
    const protoCount = {};
    reports.forEach((r) => { protoCount[r.protocol] = (protoCount[r.protocol] || 0) + 1; });

    // timeline buckets
    const ts = alerts.map((a) => a.timestamp);
    const min = Math.min(...ts), max = Math.max(...ts);
    const N = 12, span = (max - min) / N || 1;
    const buckets = new Array(N).fill(0), blabels = [];
    alerts.forEach((a) => { const i = Math.min(N - 1, Math.floor((a.timestamp - min) / span)); buckets[i]++; });
    for (let i = 0; i < N; i++) blabels.push(fmtTime(min + i * span).slice(0, 5));

    const topSrc = Object.entries(srcCount).sort((a, b) => b[1] - a[1]).slice(0, 5)
      .map(([label, value]) => ({ label, value, color: '#ff5a5f' }));
    const topProto = Object.entries(protoCount).sort((a, b) => b[1] - a[1])
      .map(([label, value]) => ({ label, value, color: PROTO_COLOR[label] || '#3ddc97' }));

    return { srcCount, typeCount, sevCount, protoCount, buckets, blabels, topSrc, topProto };
  }, [lang]);

  const uniqueSrc = Object.keys(agg.srcCount).length;
  const kpis = [
    { key: 'kpi_alerts', val: alerts.length, sub: t('alerts_detected'), color: '#3ddc97', spark: agg.buckets },
    { key: 'kpi_events', val: reports.length, sub: t('events_captured'), color: '#38bdf8', spark: [4, 8, 6, 12, 9, 14, 11, 18] },
    { key: 'kpi_sources', val: uniqueSrc, sub: t('last24'), color: '#c084fc', spark: [2, 3, 3, 4, 5, 5] },
    { key: 'kpi_threats', val: agg.sevCount.critical, sub: t('last24'), color: '#ff5a5f', spark: [1, 2, 1, 3, 4, 3, 5] },
  ];

  const typeSlices = [
    { label: 'threat_intel', value: agg.typeCount.threat_intel, color: '#ff5a5f' },
    { label: 'arp_spoof', value: agg.typeCount.arp_spoof, color: '#c084fc' },
    { label: 'heuristic', value: agg.typeCount.heuristic, color: '#fbbf24' },
  ];
  const riskSlices = ['critical', 'high', 'medium', 'low']
    .map((k) => ({ label: t(SEV[k].key), value: agg.sevCount[k], color: SEV[k].c }))
    .filter((s) => s.value > 0);

  const feed = [...alerts].slice(-7).reverse();

  return (
    <div className="screen">
      <div className="kpi-row">
        {kpis.map((k) => (
          <div className="kpi-card" key={k.key}>
            <div className="kpi-top">
              <span className="kpi-label">{t(k.key)}</span>
              <Sparkline data={k.spark} color={k.color} />
            </div>
            <div className="kpi-val mono" style={{ color: k.color }}>{k.val}</div>
            <div className="kpi-sub">{k.sub}</div>
          </div>
        ))}
      </div>

      <div className="grid-2">
        <section className="card span-2-wide">
          <div className="card-head"><h3>{t('chart_timeline')}</h3><span className="card-tag mono">{D.alerts.length} total</span></div>
          <AreaTimeline series={agg.buckets} labels={agg.blabels} />
        </section>
        <section className="card">
          <div className="card-head"><h3>{t('chart_risk')}</h3></div>
          <Donut slices={riskSlices} centerLabel={D.alerts.length} centerSub={t('nav_alerts').toLowerCase()} />
        </section>
      </div>

      <div className="grid-3">
        <section className="card">
          <div className="card-head"><h3>{t('chart_top')}</h3></div>
          <BarList items={agg.topSrc} color="#ff5a5f" />
        </section>
        <section className="card">
          <div className="card-head"><h3>{t('chart_proto')}</h3></div>
          <BarList items={agg.topProto} mono={false} />
        </section>
        <section className="card">
          <div className="card-head"><h3>{t('chart_types')}</h3></div>
          <Donut slices={typeSlices} centerLabel={typeSlices.reduce((a, s) => a + s.value, 0)} centerSub="" />
        </section>
      </div>

      <section className="card">
        <div className="card-head"><h3>{t('feed_title')}</h3><Live t={t} ts="" /></div>
        <ul className="feed">
          {feed.map((a, i) => (
            <li key={i} className="feed-row">
              <span className="feed-bar" style={{ background: SEV[alertSeverity(a)].c }}></span>
              <span className="feed-time mono">{fmtTime(a.timestamp)}</span>
              <TypeBadge a={a} />
              <span className="feed-src mono">{a.src_ip}</span>
              <span className="feed-arrow">→</span>
              <span className="feed-dst mono">{a.dst}{a.dst_port ? ':' + a.dst_port : ''}</span>
              <span className="feed-risk">{lang === 'en' && a.riskEn ? a.riskEn : a.risk}</span>
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
function Alerts({ t, lang, liveTs }) {
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState('all');
  const [open, setOpen] = useState({});
  const [rows, setRows] = useState(() => [...D.alerts].reverse());

  const types = ['all', 'threat_intel', 'arp_spoof', 'heuristic'];
  const counts = useMemo(() => {
    const c = { all: rows.length, threat_intel: 0, arp_spoof: 0, heuristic: 0 };
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
              {ty === 'all' ? t('all') : ty}<span className="chip-n">{counts[ty]}</span>
            </button>
          ))}
        </div>
        <div className="toolbar-right">
          <div className="search"><span className="search-i">⌕</span>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('search')} />
          </div>
          <Live t={t} ts={liveTs} />
          <button className="btn-danger" onClick={() => { if (confirm(lang === 'es' ? '¿Limpiar todas las alertas?' : 'Clear all alerts?')) setRows([]); }}>
            {t('clear_alerts')}
          </button>
        </div>
      </div>

      {shown.length ? (
        <div className="table-card">
          <table className="data-table">
            <thead>
              <tr>
                <th className="w-time">{t('h_time')}</th><th>{t('h_type')}</th><th>{t('h_src')}</th>
                <th>{t('h_dst')}</th><th>{t('h_proto')}</th><th>{t('h_risk')}</th><th className="w-ev">{t('h_evidence')}</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((a, i) => {
                const sev = alertSeverity(a);
                return (
                  <React.Fragment key={i}>
                    <tr className="data-row" style={{ '--sev': SEV[sev].c }}>
                      <td className="mono nowrap">{fmtTime(a.timestamp)}</td>
                      <td><TypeBadge a={a} /></td>
                      <td className="mono"><div>{a.src_ip || 'N/D'}</div><div className="sub">{a.src_mac || ''}</div></td>
                      <td className="mono"><div>{(a.dst || 'N/D') + (a.dst_port ? ':' + a.dst_port : '')}</div><div className="sub">{a.domain || ''}</div></td>
                      <td><ProtoChip p={a.protocol} /></td>
                      <td className="risk-cell">{lang === 'en' && a.riskEn ? a.riskEn : a.risk}</td>
                      <td>
                        {a.evidence ? (
                          <button className="ev-btn" onClick={() => setOpen((o) => ({ ...o, [i]: !o[i] }))}>
                            {open[i] ? t('hide') : t('view')}
                          </button>
                        ) : <span className="sub">—</span>}
                      </td>
                    </tr>
                    {open[i] && a.evidence && (
                      <tr className="ev-row"><td colSpan="7">
                        <div className="ev-box">
                          {a.type === 'arp_spoof' && (
                            <div className="ev-line"><span className="ev-k">{t('expected')}</span><span className="mono">{a.expected_mac}</span>
                              <span className="ev-k">{t('observed')}</span><span className="mono warn">{a.actual_mac}</span></div>
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
        <div className="empty">{t('none_alerts')}</div>
      )}
    </div>
  );
}

/* ============================================================
   REPORTS
============================================================ */
function Reports({ t, lang, liveTs }) {
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState('all');
  const [rows, setRows] = useState(() => [...D.reports].reverse());

  const protos = ['all', ...Array.from(new Set(D.reports.map((r) => r.protocol)))];
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
              {p === 'all' ? t('all') : p}
            </button>
          ))}
        </div>
        <div className="toolbar-right">
          <span className="count-pill mono">{shown.length} {t('events_captured')}</span>
          <div className="search"><span className="search-i">⌕</span>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('search')} />
          </div>
          <Live t={t} ts={liveTs} />
          <button className="btn-danger" onClick={() => { if (confirm(lang === 'es' ? '¿Limpiar todos los reportes?' : 'Clear all reports?')) setRows([]); }}>
            {t('clear_reports')}
          </button>
        </div>
      </div>

      {shown.length ? (
        <div className="table-card">
          <table className="data-table">
            <thead>
              <tr>
                <th className="w-time">{t('h_time')}</th><th>{t('h_src')}</th><th>{t('h_dst')}</th>
                <th>{t('h_proto')}</th><th>{t('h_domain')}</th><th className="w-size">{t('h_size')}</th>
              </tr>
            </thead>
            <tbody>
              {shown.slice(0, 400).map((r, i) => (
                <tr className="data-row plain" key={i}>
                  <td className="mono nowrap">{fmtTime(r.timestamp)}</td>
                  <td className="mono"><div>{(r.src_ip || 'N/D') + (r.src_port ? ':' + r.src_port : '')}</div><div className="sub">{r.src_mac || ''}</div></td>
                  <td className="mono"><div>{(r.dst || 'N/D') + (r.dst_port ? ':' + r.dst_port : '')}</div><div className="sub">{r.dst_mac || ''}</div></td>
                  <td><ProtoChip p={r.protocol} />{r.tcp_flags ? <span className="flags mono">{r.tcp_flags}</span> : null}</td>
                  <td className="mono dim">{r.domain || ''}</td>
                  <td className="mono nowrap">{r.size != null ? r.size + ' B' : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty">{t('none_reports')}</div>
      )}
    </div>
  );
}

/* ============================================================
   WHITELIST
============================================================ */
function Whitelist({ t, lang }) {
  const [entries, setEntries] = useState(() => [...D.whitelist]);
  const [ip, setIp] = useState('');
  const [mac, setMac] = useState('');
  const [note, setNote] = useState('');

  function add(e) {
    e.preventDefault();
    if (!ip && !mac) return;
    setEntries((es) => [...es, { key: (ip || mac) + '--' + Date.now(), ip: ip || null, mac: mac || null, note }]);
    setIp(''); setMac(''); setNote('');
  }

  return (
    <div className="screen wl-screen">
      <div className="wl-grid">
        <section className="card wl-form-card">
          <div className="card-head"><h3>{t('wl_add')}</h3></div>
          <form onSubmit={add} className="wl-form">
            <label className="field">
              <span className="field-l">{t('wl_ip')}</span>
              <input className="mono" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="192.168.1.50" />
            </label>
            <label className="field">
              <span className="field-l">{t('wl_mac')} <em>{t('wl_optional')}</em></span>
              <input className="mono" value={mac} onChange={(e) => setMac(e.target.value)} placeholder="aa:bb:cc:dd:ee:ff" />
            </label>
            <label className="field">
              <span className="field-l">{t('wl_note')}</span>
              <input value={note} onChange={(e) => setNote(e.target.value)} placeholder={lang === 'es' ? 'Ej. Impresora de oficina' : 'e.g. Office printer'} />
            </label>
            <button type="submit" className="btn-primary">{t('wl_submit')}</button>
          </form>
        </section>

        <section className="card wl-list-card">
          <div className="card-head"><h3>{t('wl_entries')}</h3><span className="card-tag mono">{entries.length} {t('wl_count')}</span></div>
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
                  <button className="wl-del" title={t('wl_remove')}
                    onClick={() => setEntries((es) => es.filter((x) => x.key !== e.key))}>✕</button>
                </li>
              ))}
            </ul>
          ) : (
            <div className="empty small">{t('wl_empty')}</div>
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
  { id: 'overview', icon: '◉', key: 'nav_overview' },
  { id: 'alerts', icon: '⚠', key: 'nav_alerts' },
  { id: 'reports', icon: '≣', key: 'nav_reports' },
  { id: 'whitelist', icon: '✓', key: 'nav_whitelist' },
];

function App() {
  const [lang, setLang] = useState(() => localStorage.getItem('ids_lang') || 'es');
  const [screen, setScreen] = useState(() => localStorage.getItem('ids_screen') || 'overview');
  const [clock, setClock] = useState(new Date());
  const [now, setNow] = useState(Math.floor(D.NOW));
  const t = (k) => (D.I18N[lang][k] || k);

  useEffect(() => { localStorage.setItem('ids_lang', lang); }, [lang]);
  useEffect(() => { localStorage.setItem('ids_screen', screen); }, [screen]);
  useEffect(() => {
    const id = setInterval(() => { setClock(new Date()); setNow((n) => n + 3); }, 3000);
    return () => clearInterval(id);
  }, []);

  const liveTs = '· ' + fmtClock(clock);
  const titleKey = NAV.find((n) => n.id === screen).key;
  const subMap = { overview: 'ov_sub', alerts: null, reports: null, whitelist: 'wl_sub' };

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark mono">IDS<span className="blink">_</span></div>
          <div className="brand-sub">{t('brand_sub')}</div>
        </div>
        <nav className="nav">
          {NAV.map((n) => (
            <button key={n.id} className={'nav-item' + (screen === n.id ? ' active' : '')} onClick={() => setScreen(n.id)}>
              <span className="nav-ic">{n.icon}</span>
              <span>{t(n.key)}</span>
              {n.id === 'alerts' && <span className="nav-badge">{D.alerts.length}</span>}
            </button>
          ))}
        </nav>
        <div className="side-foot">
          <div className="monitor">
            <span className="mon-dot"></span>
            <div>
              <div className="mon-l">{t('monitor_on')}</div>
              <div className="mon-s mono">iface: {t('monitor_iface')}</div>
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
            <h1>{t(titleKey)}</h1>
            {subMap[screen] && <span className="page-sub">{t(subMap[screen])}</span>}
          </div>
          <div className="topbar-r">
            <span className="sys-clock mono">{fmtClock(clock)}</span>
          </div>
        </header>
        <div className="content">
          {screen === 'overview' && <Overview t={t} lang={lang} now={now} />}
          {screen === 'alerts' && <Alerts t={t} lang={lang} liveTs={liveTs} />}
          {screen === 'reports' && <Reports t={t} lang={lang} liveTs={liveTs} />}
          {screen === 'whitelist' && <Whitelist t={t} lang={lang} />}
        </div>
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
