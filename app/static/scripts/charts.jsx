/* =========================================================
   IDS Console — hand-built SVG charts (no external deps)
   Terminal aesthetic: thin strokes, green signal, grid lines.
========================================================= */
const { useMemo: _useMemo } = React;

// ---- Sparkline (KPI trend) ---------------------------------------
function Sparkline({ data, color = '#3ddc97', w = 120, h = 34 }) {
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const span = max - min || 1;
  const step = w / (data.length - 1);
  const pts = data.map((v, i) => [i * step, h - ((v - min) / span) * (h - 4) - 2]);
  const line = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
  const area = line + ` L${w} ${h} L0 ${h} Z`;
  const gid = 'sp' + color.replace('#', '');
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width={w} height={h} preserveAspectRatio="none" className="spark">
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={color} stopOpacity="0.28" />
          <stop offset="1" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={area} fill={`url(#${gid})`} />
      <path d={line} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

// ---- Area timeline (alerts over time) ----------------------------
function AreaTimeline({ series, labels, height = 220, color = '#3ddc97' }) {
  const W = 760, H = height, padL = 34, padB = 26, padT = 14, padR = 8;
  const iw = W - padL - padR, ih = H - padB - padT;
  const max = Math.max(...series, 4);
  const niceMax = Math.ceil(max / 4) * 4;
  const step = iw / (series.length - 1);
  const x = (i) => padL + i * step;
  const y = (v) => padT + ih - (v / niceMax) * ih;
  const line = series.map((v, i) => (i ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(v).toFixed(1)).join(' ');
  const area = line + ` L${x(series.length - 1)} ${padT + ih} L${padL} ${padT + ih} Z`;
  const grid = [0, 0.25, 0.5, 0.75, 1].map((g) => padT + ih - g * ih);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="chart-svg" preserveAspectRatio="xMidYMid meet">
      <defs>
        <linearGradient id="areaFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={color} stopOpacity="0.30" />
          <stop offset="1" stopColor={color} stopOpacity="0.02" />
        </linearGradient>
      </defs>
      {grid.map((gy, i) => (
        <g key={i}>
          <line x1={padL} y1={gy} x2={W - padR} y2={gy} stroke="#1c2730" strokeWidth="1" strokeDasharray="2 4" />
          <text x={padL - 8} y={gy + 3} textAnchor="end" className="axis-text">
            {Math.round((1 - (gy - padT) / ih) * niceMax)}
          </text>
        </g>
      ))}
      <path d={area} fill="url(#areaFill)" />
      <path d={line} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" />
      {series.map((v, i) => (
        <circle key={i} cx={x(i)} cy={y(v)} r="2.4" fill="#0a0e12" stroke={color} strokeWidth="1.4" />
      ))}
      {labels.map((l, i) =>
        i % 2 === 0 ? (
          <text key={i} x={x(i)} y={H - 8} textAnchor="middle" className="axis-text">{l}</text>
        ) : null
      )}
    </svg>
  );
}

// ---- Donut (risk / type distribution) ----------------------------
function Donut({ slices, total, centerLabel, centerSub }) {
  const size = 168, r = 64, sw = 20, cx = size / 2, cy = size / 2;
  const C = 2 * Math.PI * r;
  let acc = 0;
  const sum = total || slices.reduce((a, s) => a + s.value, 0) || 1;
  return (
    <div className="donut-wrap">
      <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size} className="donut">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#161f26" strokeWidth={sw} />
        {slices.map((s, i) => {
          const frac = s.value / sum;
          const dash = frac * C;
          const el = (
            <circle key={i} cx={cx} cy={cy} r={r} fill="none" stroke={s.color} strokeWidth={sw}
              strokeDasharray={`${dash} ${C - dash}`} strokeDashoffset={-acc}
              transform={`rotate(-90 ${cx} ${cy})`} strokeLinecap="butt" />
          );
          acc += dash;
          return el;
        })}
        <text x={cx} y={cy - 2} textAnchor="middle" className="donut-num">{centerLabel}</text>
        <text x={cx} y={cy + 16} textAnchor="middle" className="donut-sub">{centerSub}</text>
      </svg>
      <ul className="legend">
        {slices.map((s, i) => (
          <li key={i}>
            <span className="dot" style={{ background: s.color }}></span>
            <span className="lg-label">{s.label}</span>
            <span className="lg-val">{s.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---- Ranked horizontal bars (top IPs / protocols) ----------------
function BarList({ items, color = '#3ddc97', mono = true }) {
  const max = Math.max(...items.map((i) => i.value), 1);
  return (
    <ul className="barlist">
      {items.map((it, i) => (
        <li key={i}>
          <span className={'bl-label' + (mono ? ' mono' : '')}>{it.label}</span>
          <span className="bl-track">
            <span className="bl-fill" style={{ width: (it.value / max) * 100 + '%', background: it.color || color }}></span>
          </span>
          <span className="bl-val">{it.value}</span>
        </li>
      ))}
    </ul>
  );
}

Object.assign(window, { Sparkline, AreaTimeline, Donut, BarList });
