// ============================================================
// scan-ui.js — UI animatsiyalar, timer, toast, tab
// ============================================================

// Matrix rain
(function () {
  const c = document.getElementById('matrix');
  const ctx = c.getContext('2d');
  function resize() { c.width = window.innerWidth; c.height = window.innerHeight; }
  resize();
  window.addEventListener('resize', resize);
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()アイウエオカキクケコ';
  const cols = Math.floor(window.innerWidth / 16);
  const drops = Array(cols).fill(1);
  setInterval(() => {
    ctx.fillStyle = 'rgba(0,3,5,0.05)';
    ctx.fillRect(0, 0, c.width, c.height);
    ctx.fillStyle = '#00ff88';
    ctx.font = '14px Share Tech Mono';
    drops.forEach((y, i) => {
      const ch = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(ch, i * 16, y * 16);
      if (y * 16 > c.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    });
  }, 50);
})();

// Clock
setInterval(() => {
  const n = new Date();
  document.getElementById('sysTime').textContent = n.toTimeString().slice(0, 8);
}, 1000);

// Global state
window._file = null;
window._data = null;
window._timerInt = null;
window._timerSec = 0;

// Tab switching
function switchTab(id, el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('tab-' + id).classList.add('active');
  hideAll();
}

// Toast
function toast(msg, dur = 2500) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), dur);
}

// Scanning overlay
function showScan(title, sub, emoji = '🔍') {
  document.getElementById('scanOverlay').classList.add('show');
  document.getElementById('scanTitle').textContent = title;
  document.getElementById('scanSub').textContent = sub;
  document.getElementById('scanEmoji').textContent = emoji;
  document.getElementById('results').style.display = 'none';
  document.getElementById('results').classList.remove('show');
  startTimer();
  animateEngines();
}

function hideAll() {
  document.getElementById('scanOverlay').classList.remove('show');
  document.getElementById('results').style.display = 'none';
  stopTimer();
}

function newScan() {
  hideAll();
  ['urlInput', 'hashInput', 'ipInput', 'textInput'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  window._file = null;
  document.getElementById('fileInfo').classList.remove('show');
}

// Timer
function startTimer() {
  window._timerSec = 0;
  stopTimer();
  window._timerInt = setInterval(() => {
    window._timerSec++;
    const m = String(Math.floor(window._timerSec / 60)).padStart(2, '0');
    const s = String(window._timerSec % 60).padStart(2, '0');
    document.getElementById('scanTimer').textContent = m + ':' + s;
  }, 1000);
}

function stopTimer() { clearInterval(window._timerInt); }

// Engine animation
const ENGINE_NAMES = ['Kaspersky', 'Bitdefender', 'ESET', 'Sophos', 'McAfee', 'Avast', 'Norton', 'CrowdStrike', 'Malwarebytes', 'Symantec', 'Trend Micro', 'F-Secure'];

function animateEngines() {
  const box = document.getElementById('scanEngines');
  box.innerHTML = ENGINE_NAMES.map(e => `<span class="eng-chip" id="ec-${e.replace(/\s/g, '')}">${e}</span>`).join('');
  let i = 0;
  const iv = setInterval(() => {
    if (i >= ENGINE_NAMES.length) { clearInterval(iv); return; }
    document.getElementById('ec-' + ENGINE_NAMES[i].replace(/\s/g, ''))?.classList.add('active');
    i++;
  }, 200);
}

// File handling
function handleFile(input) {
  if (input.files[0]) setFile(input.files[0]);
}

function setFile(f) {
  window._file = f;
  document.getElementById('fileName').textContent = f.name;
  document.getElementById('fileSize').textContent = fmtSize(f.size);
  document.getElementById('fileInfo').classList.add('show');
}

function fmtSize(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(1) + ' MB';
}

// Drag & drop
document.addEventListener('DOMContentLoaded', () => {
  const dz = document.getElementById('dropZone');
  if (!dz) return;
  dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag'));
  dz.addEventListener('drop', e => {
    e.preventDefault();
    dz.classList.remove('drag');
    const f = e.dataTransfer.files[0];
    if (f) setFile(f);
  });
});

// Export
function copyReport() {
  if (!window._data) return;
  const s = window._data.attrs?.stats || {};
  const mal = s.malicious || 0, sus = s.suspicious || 0;
  const total = Object.values(s).reduce((a, b) => a + b, 0);
  const risk = Math.round(((mal + sus * .5) / Math.max(total, 1)) * 100);
  navigator.clipboard.writeText([
    '=== THREATSCAN PRO HISOBOT ===',
    'Sana: ' + new Date(window._data.ts).toLocaleString(),
    'Maqsad: ' + window._data.meta.value,
    'Tur: ' + window._data.meta.type.toUpperCase(),
    '',
    'Xavfli: ' + mal + ' | Shubhali: ' + sus + ' | Jami: ' + total,
    'Xavf: ' + risk + '%',
    mal > 0 ? 'NATIJA: XAVFLI' : sus > 0 ? 'NATIJA: SHUBHALI' : 'NATIJA: XAVFSIZ',
  ].join('\n')).then(() => toast('[OK] NUSXALANDI'));
}

function dlJSON() {
  if (!window._data) return;
  const a = document.createElement('a');
  a.href = 'data:application/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(window._data, null, 2));
  a.download = 'threatscan-' + Date.now() + '.json';
  a.click();
  toast('[DL] JSON YUKLANDI');
}

function dlHTML() {
  if (!window._data) return;
  const s = window._data.attrs?.stats || {};
  const mal = s.malicious || 0, sus = s.suspicious || 0;
  const total = Object.values(s).reduce((a, b) => a + b, 0);
  const risk = Math.round(((mal + sus * .5) / Math.max(total, 1)) * 100);
  const color = mal > 0 ? '#ff2244' : sus > 0 ? '#ffcc00' : '#00ff88';
  const engs = Object.entries(window._data.attrs?.results || {}).slice(0, 60);
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>ThreatScan Report</title></head>
<body style="background:#000305;color:#c8ffe0;font-family:monospace;padding:40px;max-width:820px;margin:auto">
<h1 style="color:#00ff88;font-family:sans-serif;letter-spacing:3px;margin-bottom:4px">THREATSCAN PRO</h1>
<p style="color:#2a4a3a;font-size:11px;margin-bottom:28px">${new Date(window._data.ts).toLocaleString()} · ${window._data.meta.value}</p>
<div style="background:#050d1a;border:1px solid rgba(0,255,136,0.2);border-radius:6px;padding:22px;margin-bottom:22px">
  <div style="font-size:28px;font-weight:700;color:${color};margin-bottom:8px">${mal > 0 ? 'XAVFLI' : sus > 0 ? 'SHUBHALI' : 'XAVFSIZ'} · ${risk}%</div>
  <div style="color:#5a8a6a;font-size:13px">Xavfli: ${mal} · Shubhali: ${sus} · Xavfsiz: ${s.undetected || 0} · Jami: ${total}</div>
</div>
<table style="width:100%;border-collapse:collapse">
<tr style="background:#071022"><th style="padding:9px 12px;text-align:left;font-size:10px;color:#2a4a3a">ENGINE</th><th style="padding:9px 12px;text-align:left;font-size:10px;color:#2a4a3a">NATIJA</th></tr>
${engs.map(([e, r]) => `<tr style="border-bottom:1px solid #071022"><td style="padding:6px 12px;font-size:11px;color:#5a8a6a">${e}</td><td style="padding:6px 12px;font-size:11px;color:${r.category === 'malicious' ? '#ff2244' : r.category === 'suspicious' ? '#ffcc00' : '#2a4a3a'};font-weight:600">${r.result || r.category || '—'}</td></tr>`).join('')}
</table></body></html>`;
  const a = document.createElement('a');
  a.href = 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
  a.download = 'threatscan-report-' + Date.now() + '.html';
  a.click();
  toast('[DL] HTML YUKLANDI');
}
