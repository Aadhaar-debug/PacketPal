'use strict';

const PP = window.PacketPal;
const store = new window.Analyzers.PacketStore();

let capturing = false;
let activeTab = 'devices';
let activeFilter = { type: 'all', value: '' };
let renderTimer = null;
let currentIface = '';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');

// Plain-English intros for each tab.
const EXPLAIN = {
  devices: '<b>Who is on your network?</b> Every gadget — phones, laptops, TVs, smart bulbs — shows up here the moment it talks. We guess the maker from its hardware address and learn its name when the network announces it.',
  credentials: '<b>Is anything leaking your logins?</b> Secure sites (HTTPS) hide your passwords. Old or misconfigured services (plain HTTP, FTP, Telnet, old email) send them <b>in the clear</b>, where anyone on the network can read them. PacketPal flags these exposures so you can fix them — it does <b>not</b> store the actual passwords.',
  anomalies: '<b>Anything suspicious?</b> PacketPal watches for tell-tale attack patterns — a device scanning lots of ports (hunting for open doors), or two devices fighting over one address (a classic man-in-the-middle trick).',
  media: '<b>Pictures &amp; video crossing the wire.</b> When a device loads an image or video over an <b>unencrypted</b> connection, it is visible on the network. This shows what was sent and by whom. (Encrypted sites — most of the web — stay private and will not appear here.)',
  services: '<b>Open doors on your devices.</b> A “port” is a door into a device. When PacketPal sees a device answer a knock, it knows that door is open and lists what service is likely behind it. Unexpected open doors are worth a closer look.',
  traffic: '<b>Everything, as it happens.</b> This is the raw feed in friendly language. Use the buttons below to zero in — they appear automatically as PacketPal discovers new kinds of traffic.',
};

// ---------- boot ----------
async function boot() {
  for (const [k, v] of Object.entries(EXPLAIN)) {
    const el = $('exp-' + k); if (el) el.innerHTML = v;
  }
  wireTabs();

  const st = await PP.status();
  if (!st.installed) {
    $('engineStatus').textContent = 'Wireshark engine not found';
    $('engineStatus').className = 'engine bad';
    showBanner('err',
      '<h3>Wireshark engine missing</h3>Install it once with Homebrew, then reopen PacketPal:' +
      codeLine('brew install wireshark'));
    return;
  }
  $('engineStatus').textContent = 'Engine: tshark ready';
  $('engineStatus').className = 'engine ok';

  const ifaces = await PP.listInterfaces();
  const sel = $('iface');
  sel.innerHTML = '';
  if (!ifaces.length) {
    sel.innerHTML = '<option>No interfaces (need permission)</option>';
  } else {
    for (const i of ifaces) {
      const o = document.createElement('option');
      o.value = i.id; o.textContent = i.label;
      sel.appendChild(o);
    }
    currentIface = ifaces[0].id;
    $('captureBtn').disabled = false;
  }

  await verifyPermission();

  $('captureBtn').addEventListener('click', toggleCapture);
  sel.addEventListener('change', async (e) => { currentIface = e.target.value; await verifyPermission(); });

  PP.onPackets((batch) => { for (const p of batch) store.ingest(p); });
  PP.onError(handleCaptureError);
  PP.onStopped(() => { if (capturing) stopCapture(); });

  renderAll();
}

async function verifyPermission() {
  const res = await PP.checkPermission(currentIface);
  if (res.ok) {
    hideBanner();
    $('captureHint').textContent = 'Ready — press start to watch live.';
    return true;
  }
  if (res.reason === 'permission') {
    const cmd = await PP.permissionFixCommand();
    showBanner('warn',
      '<h3>One-time setup: allow PacketPal to listen</h3>' +
      'macOS blocks packet capture until you install Wireshark’s permission helper. ' +
      'Paste this into Terminal (it will ask for your password), then reopen PacketPal:' +
      codeLine(cmd));
    $('captureBtn').disabled = true;
    $('captureHint').textContent = 'Capture permission needed (see banner).';
  } else {
    $('captureHint').textContent = 'Could not verify permission.';
  }
  return false;
}

// ---------- capture ----------
async function toggleCapture() { capturing ? stopCapture() : startCapture(); }

async function startCapture() {
  store.reset();
  activeFilter = { type: 'all', value: '' };
  await PP.startCapture(currentIface);
  capturing = true;
  const btn = $('captureBtn');
  btn.textContent = 'Stop watching';
  btn.classList.add('recording');
  $('captureHint').textContent = 'Watching live…';
  renderTimer = setInterval(renderAll, 600);
}

async function stopCapture() {
  await PP.stopCapture();
  capturing = false;
  const btn = $('captureBtn');
  btn.textContent = 'Start watching';
  btn.classList.remove('recording');
  $('captureHint').textContent = 'Stopped. Results are still here to explore.';
  if (renderTimer) { clearInterval(renderTimer); renderTimer = null; }
  renderAll();
}

async function handleCaptureError(msg) {
  if (msg === 'permission') { await verifyPermission(); if (capturing) stopCapture(); return; }
  showBanner('err', '<h3>Capture problem</h3>' + esc(msg));
  if (capturing) stopCapture();
}

// ---------- tabs ----------
function wireTabs() {
  document.querySelectorAll('.card').forEach((c) => {
    c.addEventListener('click', () => selectTab(c.dataset.tab));
  });
}
function selectTab(tab) {
  activeTab = tab;
  document.querySelectorAll('.card').forEach((c) => c.classList.toggle('active', c.dataset.tab === tab));
  document.querySelectorAll('.panel').forEach((p) => p.classList.toggle('active', p.dataset.panel === tab));
  renderAll();
}

// ---------- rendering ----------
function renderAll() {
  const s = store.snapshot();

  $('statPackets').textContent = fmt(s.totalPackets);
  $('statData').textContent = humanBytes(s.totalBytes);
  $('statTime').textContent = Math.round(s.durationSec) + 's';

  setCount('devices', s.counts.devices);
  setCount('credentials', s.counts.credentials, true);
  setCount('anomalies', s.counts.anomalies, true);
  setCount('media', s.counts.media);
  setCount('services', s.counts.services);
  setCount('traffic', s.totalPackets);

  switch (activeTab) {
    case 'devices': renderDevices(s); break;
    case 'credentials': renderCredentials(s); break;
    case 'anomalies': renderAnomalies(s); break;
    case 'media': renderMedia(s); break;
    case 'services': renderServices(s); break;
    case 'traffic': renderTraffic(s); break;
  }
}

function setCount(tab, n, pulse) {
  $('cnt-' + tab).textContent = fmt(n);
  const card = document.querySelector(`.card[data-tab="${tab}"]`);
  if (!card) return;
  let dot = card.querySelector('.pulse');
  if (pulse && n > 0) { if (!dot) { dot = document.createElement('span'); dot.className = 'pulse'; card.appendChild(dot); } }
  else if (dot) dot.remove();
}

function emptyState(icon, text) {
  return `<div class="empty"><span class="big">${icon}</span>${text}</div>`;
}

function renderDevices(s) {
  const el = $('list-devices');
  if (!s.devices.length) { el.innerHTML = emptyState('👀', capturing ? 'Listening… devices will pop up as they talk.' : 'Press <b>Start watching</b> to discover devices.'); return; }
  el.innerHTML = s.devices.map((d) => {
    const name = d.hostname || d.vendor || (d.local ? 'Local device' : 'Internet server');
    const ico = d.local ? '💻' : '☁️';
    return `<div class="row">
      <div class="av">${ico}</div>
      <div class="main">
        <div class="title">${esc(name)}
          <span class="badge ${d.local ? 'local' : 'ext'}">${d.local ? 'on your network' : 'internet'}</span></div>
        <div class="sub mono">${esc(d.ip)}${d.mac ? ' · ' + esc(d.mac) : ''}${d.vendor ? ' · ' + esc(d.vendor) : ''}</div>
      </div>
      <div class="meta">${fmt(d.packets)} pkts<br>${humanBytes(d.bytes)}</div>
    </div>`;
  }).join('');
}

function renderCredentials(s) {
  const el = $('list-credentials');
  if (!s.credentials.length) { el.innerHTML = emptyState('✅', 'No cleartext logins spotted. That is good — it means logins are staying encrypted.'); return; }
  el.innerHTML = s.credentials.map((c) => `<div class="row danger">
      <div class="av">🔓</div>
      <div class="main">
        <div class="title">${esc(c.summary)}<span class="badge hi">${esc(c.protocol)}</span></div>
        <div class="sub mono">${esc(c.endpoints)}</div>
      </div>
      <div class="meta">${clock(c.t)}</div>
    </div>`).join('');
}

function renderAnomalies(s) {
  const el = $('list-anomalies');
  if (!s.anomalies.length) { el.innerHTML = emptyState('🛡️', 'Nothing unusual so far. PacketPal keeps watching for scans and spoofing.'); return; }
  el.innerHTML = s.anomalies.map((a) => `<div class="row danger">
      <div class="av">⚠️</div>
      <div class="main">
        <div class="title">${esc(a.title)}</div>
        <div class="sub">${esc(a.detail)}</div>
      </div>
      <div class="meta">${clock(a.t)}</div>
    </div>`).join('');
}

function renderMedia(s) {
  const el = $('list-media');
  if (!s.media.length) { el.innerHTML = emptyState('🖼️', capturing ? 'No unencrypted images or video yet. Most modern sites are encrypted, so this stays quiet.' : 'Press start to watch for images and video.'); return; }
  el.innerHTML = s.media.map((m) => `<div class="row">
      <div class="av">${m.kind === 'video' ? '🎬' : '🖼️'}</div>
      <div class="main">
        <div class="title">${m.kind === 'video' ? 'Video' : 'Image'} — ${esc(m.contentType)}</div>
        <div class="sub mono">${esc(m.host)}${esc(m.uri)} ${m.src ? '· from ' + esc(m.src) : ''}</div>
      </div>
      <div class="meta">${clock(m.t)}</div>
    </div>`).join('');
}

function renderServices(s) {
  const el = $('list-services');
  if (!s.services.length) { el.innerHTML = emptyState('🚪', 'No open doors seen yet. They appear when a device answers a connection.'); return; }
  el.innerHTML = s.services.map((sv) => `<div class="row">
      <div class="av">🚪</div>
      <div class="main">
        <div class="title">${esc(sv.service)}
          <span class="badge ${sv.local ? 'local' : 'ext'}">${sv.local ? 'your device' : 'internet'}</span></div>
        <div class="sub mono">${esc(sv.ip)} · port ${esc(sv.port)}</div>
      </div>
    </div>`).join('');
}

// ---- dynamic filter buttons + traffic table ----
const CATEGORY_FILTERS = [
  { key: 'all', label: 'Everything', test: () => true },
  { key: 'local', label: 'On my network', test: (r) => r.tags.includes('local') },
  { key: 'web', label: 'Web (HTTP)', test: (r) => r.tags.includes('web') },
  { key: 'secure', label: 'Secure (HTTPS)', test: (r) => r.tags.includes('secure') },
  { key: 'dns', label: 'Lookups (DNS)', test: (r) => r.tags.includes('dns') },
  { key: 'media', label: 'Photos & video', test: (r) => r.tags.includes('media') },
  { key: 'exposed-login', label: 'Exposed logins', test: (r) => r.tags.includes('exposed-login') },
];

function matchFilter(r) {
  if (activeFilter.type === 'all') return true;
  if (activeFilter.type === 'tag') return r.tags.includes(activeFilter.value);
  if (activeFilter.type === 'proto') return r.proto === activeFilter.value;
  if (activeFilter.type === 'host') return (r.info || '').indexOf(activeFilter.value) >= 0 || r.dst === activeFilter.value;
  return true;
}

function renderTraffic(s) {
  renderFilters(s);
  const rows = [];
  for (let i = store.packets.length - 1; i >= 0 && rows.length < 300; i--) {
    const r = store.packets[i];
    if (matchFilter(r)) rows.push(r);
  }
  const el = $('list-traffic');
  if (!store.packets.length) { el.innerHTML = emptyState('🌐', capturing ? 'Listening for traffic…' : 'Press start to see live traffic.'); return; }
  el.innerHTML = `<table><thead><tr>
      <th>#</th><th>Time</th><th>Type</th><th>From</th><th>To</th><th>What happened</th>
    </tr></thead><tbody>${rows.map((r) => `<tr>
      <td class="mono">${r.n}</td>
      <td>${clock(r.t)}</td>
      <td class="proto"><span>${esc(r.proto)}</span></td>
      <td class="mono">${esc(r.src)}${r.sport ? ':' + esc(r.sport) : ''}</td>
      <td class="mono">${esc(r.dst)}${r.dport ? ':' + esc(r.dport) : ''}</td>
      <td title="${esc(r.info)}">${esc(r.info)}</td>
    </tr>`).join('')}</tbody></table>`;
}

function renderFilters(s) {
  const counts = {};
  for (const r of store.packets) for (const t of r.tags) counts[t] = (counts[t] || 0) + 1;

  const chips = [];
  for (const f of CATEGORY_FILTERS) {
    if (f.key !== 'all' && f.key !== 'local' && !counts[f.key]) continue; // only show when present
    const type = f.key === 'all' ? 'all' : 'tag';
    const n = f.key === 'all' ? store.packets.length : (counts[f.key] || 0);
    chips.push(chip(f.label, type, f.key, n));
  }
  // protocol chips (auto-generated from what has been seen)
  for (const [proto, n] of s.topProtocols.slice(0, 8)) {
    chips.push(chip(proto, 'proto', proto, n));
  }
  // top destination hosts/domains
  for (const [host, n] of s.topHosts.slice(0, 6)) {
    chips.push(chip('🔗 ' + host, 'host', host, n));
  }
  $('filters').innerHTML = chips.join('');
  document.querySelectorAll('#filters .chip').forEach((c) => {
    c.addEventListener('click', () => {
      activeFilter = { type: c.dataset.type, value: c.dataset.value };
      renderTraffic(store.snapshot());
    });
  });
}

function chip(label, type, value, n) {
  const active = (activeFilter.type === type && (type === 'all' || activeFilter.value === value));
  return `<button class="chip ${active ? 'active' : ''}" data-type="${esc(type)}" data-value="${esc(value)}">${esc(label)}<span class="n">${fmt(n)}</span></button>`;
}

// ---------- banner + helpers ----------
function showBanner(kind, html) { const b = $('banner'); b.className = 'banner ' + kind; b.innerHTML = html; }
function hideBanner() { $('banner').className = 'banner hidden'; }
function codeLine(cmd) {
  return `<div><code id="cmd">${esc(cmd)}</code><button class="copy" id="copyBtn">Copy</button></div>`;
}
document.addEventListener('click', (e) => {
  if (e.target && e.target.id === 'copyBtn') {
    const c = $('cmd'); if (c) { navigator.clipboard.writeText(c.textContent); e.target.textContent = 'Copied!'; setTimeout(() => e.target.textContent = 'Copy', 1500); }
  }
});

function fmt(n) { return (n || 0).toLocaleString('en-US'); }
function humanBytes(b) {
  b = b || 0;
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}
function clock(epoch) {
  const d = new Date(epoch * 1000);
  return d.toLocaleTimeString('en-US', { hour12: false });
}

boot();
