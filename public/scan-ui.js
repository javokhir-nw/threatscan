// ============================================================
// scan-ui.js — UI animatsiyalar, timer, toast, tab
// ============================================================

function dlHTML() {
  if (!window._data) return;
  const d = window._data;
  const ts = new Date(d.ts).toLocaleString();

  function buildHTML(title, verdictColor, verdictText, riskPct, summaryHTML, findingsHTML, aiHTML, metaHTML) {
    const barColor = riskPct > 60 ? '#ff2244' : riskPct > 20 ? '#ffcc00' : '#00ff88';
    return `<!DOCTYPE html>
<html lang="uz">
<head>
<meta charset="UTF-8">
<title>ThreatScan Pro — Hisobot</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#000305;color:#c8ffe0;font-family:'Courier New',monospace;padding:40px 20px;min-height:100vh}
  .wrap{max-width:860px;margin:auto}
  .header{border-bottom:1px solid rgba(0,255,136,0.2);padding-bottom:20px;margin-bottom:28px;display:flex;justify-content:space-between;align-items:flex-end}
  .logo{font-size:22px;font-weight:900;letter-spacing:3px;color:#00ff88}
  .logo span{color:#0af}
  .meta{font-size:11px;color:#3a6a4a;text-align:right;line-height:1.7}
  .verdict-box{border-radius:8px;padding:24px 28px;margin-bottom:24px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px}
  .verdict-box.ok{background:rgba(0,255,136,0.05);border:1px solid rgba(0,255,136,0.3)}
  .verdict-box.warn{background:rgba(255,204,0,0.05);border:1px solid rgba(255,204,0,0.3)}
  .verdict-box.bad{background:rgba(255,34,68,0.05);border:1px solid rgba(255,34,68,0.3)}
  .verdict-title{font-size:26px;font-weight:900;letter-spacing:2px}
  .verdict-sub{font-size:12px;color:#5a8a6a;margin-top:6px}
  .verdict-pct{font-size:44px;font-weight:900;text-align:right;letter-spacing:-1px}
  .verdict-pct-label{font-size:10px;letter-spacing:2px;opacity:0.6;text-align:right}
  .risk-bar-wrap{margin-bottom:24px}
  .risk-bar-label{display:flex;justify-content:space-between;font-size:10px;color:#3a6a4a;margin-bottom:6px;letter-spacing:1px}
  .risk-bar-track{height:8px;background:rgba(255,255,255,0.05);border-radius:4px;overflow:hidden}
  .risk-bar-fill{height:100%;border-radius:4px;background:${barColor};width:${riskPct}%}
  .stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
  .stat-card{background:#050d1a;border:1px solid #0d1f2d;border-radius:6px;padding:14px 16px}
  .stat-label{font-size:10px;color:#3a6a4a;letter-spacing:1px;margin-bottom:6px}
  .stat-val{font-size:20px;font-weight:700}
  .section{background:#050d1a;border:1px solid #0d1f2d;border-radius:6px;margin-bottom:18px;overflow:hidden}
  .section-head{padding:12px 16px;border-bottom:1px solid #0d1f2d;font-size:10px;color:#3a6a4a;letter-spacing:2px;display:flex;justify-content:space-between;align-items:center}
  .section-count{background:rgba(0,255,136,0.1);color:#00ff88;padding:2px 8px;border-radius:3px;font-size:10px}
  table{width:100%;border-collapse:collapse}
  th{padding:9px 14px;text-align:left;font-size:10px;color:#2a4a3a;letter-spacing:1px;background:#030a10}
  td{padding:8px 14px;font-size:11px;border-bottom:1px solid #071022;vertical-align:top}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:rgba(255,255,255,0.02)}
  .tag-bad{color:#ff2244;font-weight:700}
  .tag-warn{color:#ffcc00;font-weight:700}
  .tag-ok{color:#00ff88}
  .tag-info{color:#0af}
  .ai-block{padding:18px 20px}
  .ai-label{font-size:10px;color:#3a6a4a;letter-spacing:2px;margin-bottom:12px}
  .ai-level{font-size:13px;font-weight:700;margin-bottom:10px}
  .ai-row{display:flex;gap:8px;margin-bottom:6px;font-size:11px}
  .ai-key{color:#3a6a4a;width:90px;flex-shrink:0}
  .ai-val{color:#c8ffe0;line-height:1.5}
  .ai-tags{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px}
  .ai-tag{background:rgba(255,204,0,0.1);color:#ffcc00;padding:2px 8px;border-radius:3px;font-size:10px}
  .ai-tip{background:rgba(0,255,136,0.08);border:1px solid rgba(0,255,136,0.2);border-radius:4px;padding:10px 14px;margin-top:12px;font-size:11px;color:#00ff88;line-height:1.5}
  .footer{margin-top:32px;padding-top:16px;border-top:1px solid #0d1f2d;display:flex;justify-content:space-between;font-size:10px;color:#2a4a3a}
  .meta-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:16px}
  .meta-row{display:flex;justify-content:space-between;font-size:11px;padding:5px 0;border-bottom:1px solid #071022}
  .meta-row:last-child{border-bottom:none}
  .mk{color:#3a6a4a}
  .mv{color:#c8ffe0;font-weight:600}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div>
      <div class="logo">⬡ THREAT<span>SCAN</span></div>
      <div style="font-size:10px;color:#3a6a4a;letter-spacing:2px;margin-top:4px">ADVANCED THREAT INTELLIGENCE PLATFORM</div>
    </div>
    <div class="meta">
      <div>${ts}</div>
      <div>${title}</div>
    </div>
  </div>
  ${verdictHTML(verdictColor, verdictText, riskPct)}
  <div class="risk-bar-wrap">
    <div class="risk-bar-label"><span>XAVF DARAJASI GRAFIGI</span><span style="color:${barColor}">${riskPct}% — ${riskPct>60?'YUQORI XAVF':riskPct>20?"O'RTA XAVF":'QUYI XAVF'}</span></div>
    <div class="risk-bar-track"><div class="risk-bar-fill"></div></div>
  </div>
  ${summaryHTML}
  ${aiHTML}
  ${findingsHTML}
  ${metaHTML}
  <div class="footer">
    <span>ThreatScan Pro · Avtomatik hisobot</span>
    <span>${ts}</span>
  </div>
</div>
</body>
</html>`;
  }

  function verdictHTML(color, text, pct) {
    const cls = color === '#ff2244' ? 'bad' : color === '#ffcc00' ? 'warn' : 'ok';
    const sub = pct > 60 ? 'Yuqori xavf darajasi aniqlandi' : pct > 20 ? "O'rta xavf darajasi" : 'Tahdid aniqlanmadi';
    return `<div class="verdict-box ${cls}">
      <div>
        <div class="verdict-title" style="color:${color}">${text}</div>
        <div class="verdict-sub">${sub}</div>
      </div>
      <div>
        <div class="verdict-pct" style="color:${color}">${pct}%</div>
        <div class="verdict-pct-label" style="color:${color}">XAVF DARAJASI</div>
      </div>
    </div>`;
  }

  if (d.meta?.type === 'text') {
    const findings = d.findings || [];
    const malF = findings.filter(f => f.status === 'bad').length;
    const warnF = findings.filter(f => f.status === 'warn').length;
    const cleanF = findings.filter(f => f.status === 'ok').length;
    const risk = d.totalRisk || 0;
    const verdictColor = malF > 0 || risk > 60 ? '#ff2244' : warnF > 0 || risk > 20 ? '#ffcc00' : '#00ff88';
    const verdictText = malF > 0 || risk > 60 ? 'XAVFLI MATN' : warnF > 0 || risk > 20 ? 'SHUBHALI MATN' : 'XAVFSIZ MATN';

    const summaryHTML = `<div class="stats-row">
      <div class="stat-card"><div class="stat-label">JAMI TOPILDI</div><div class="stat-val" style="color:#0af">${findings.length}</div></div>
      <div class="stat-card"><div class="stat-label">XAVFLI</div><div class="stat-val" style="color:${malF>0?'#ff2244':'#3a6a4a'}">${malF}</div></div>
      <div class="stat-card"><div class="stat-label">SHUBHALI</div><div class="stat-val" style="color:${warnF>0?'#ffcc00':'#3a6a4a'}">${warnF}</div></div>
      <div class="stat-card"><div class="stat-label">XAVFSIZ</div><div class="stat-val" style="color:#00ff88">${cleanF}</div></div>
    </div>`;

    const ai = d.aiResult;
    const aiColor = ai?.xavf_darajasi === 'XAVFLI' ? '#ff2244' : ai?.xavf_darajasi === 'SHUBHALI' ? '#ffcc00' : '#00ff88';
    const aiHTML = ai ? `<div class="section" style="margin-bottom:18px">
      <div class="section-head">// GEMINI AI TAHLIL <span class="section-count" style="color:${aiColor}">${ai.xavf_darajasi||'—'}</span></div>
      <div class="ai-block">
        <div class="ai-level" style="color:${aiColor}">${ai.xavf_darajasi||'—'} · ${ai.matn_turi||'—'} · ${ai.til||'—'}</div>
        <div class="ai-row"><span class="ai-key">Xulosa</span><span class="ai-val">${ai.xulosa||'—'}</span></div>
        ${ai.sabab?.length ? `<div class="ai-row"><span class="ai-key">Sabablar</span><div><div class="ai-tags">${ai.sabab.map(s=>`<span class="ai-tag">${s}</span>`).join('')}</div></div></div>` : ''}
        ${ai.tavsiya ? `<div class="ai-tip">💡 ${ai.tavsiya}</div>` : ''}
      </div>
    </div>` : `<div class="section" style="margin-bottom:18px">
      <div class="section-head">// GEMINI AI TAHLIL</div>
      <div style="padding:16px;font-size:11px;color:#3a6a4a">AI tahlil mavjud emas (Gemini ulanmagan yoki xato yuz berdi)</div>
    </div>`;

    const findingsHTML = `<div class="section">
      <div class="section-head">// TOPILGAN ELEMENTLAR <span class="section-count">${findings.length} TA</span></div>
      <table>
        <tr><th>TUR</th><th>QIYMAT</th><th>TAFSILOT</th><th>NATIJA</th></tr>
        ${findings.length ? findings.map(f => {
          const sc = f.status === 'bad' ? 'tag-bad' : f.status === 'warn' ? 'tag-warn' : f.status === 'info' ? 'tag-info' : 'tag-ok';
          const st = f.status === 'bad' ? 'XAVFLI' : f.status === 'warn' ? 'SHUBHALI' : f.status === 'info' ? "MA'LUMOT" : 'XAVFSIZ';
          return `<tr><td class="tag-info">[${f.type}]</td><td>${f.value}</td><td style="color:#5a8a6a">${f.detail||'—'}</td><td class="${sc}">${st}</td></tr>`;
        }).join('') : '<tr><td colspan="4" style="text-align:center;color:#3a6a4a;padding:20px">Element topilmadi</td></tr>'}
      </table>
    </div>`;

    const text = d.text || '';
    const metaHTML = `<div class="section" style="margin-top:18px">
      <div class="section-head">// TEXNIK MA'LUMOTLAR</div>
      <div class="meta-grid">
        <div>
          ${[['Belgilar',text.length],["So'zlar",text.split(/\s+/).length],['Linklar',d.findings?.filter(f=>f.type==='URL').length||0],['Xavf darajasi',risk+'%']].map(([k,v])=>`<div class="meta-row"><span class="mk">${k}</span><span class="mv">${v}</span></div>`).join('')}
        </div>
        <div>
          ${[['Xavfli',malF],['Shubhali',warnF],['Xavfsiz',cleanF],['Jami',findings.length]].map(([k,v])=>`<div class="meta-row"><span class="mk">${k}</span><span class="mv">${v}</span></div>`).join('')}
        </div>
      </div>
    </div>`;

    const html = buildHTML('MATN TAHLIL', verdictColor, verdictText, risk, summaryHTML, findingsHTML, aiHTML, metaHTML);
    const a = document.createElement('a');
    a.href = 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
    a.download = 'threatscan-text-' + Date.now() + '.html';
    a.click();
    toast('[DL] HTML YUKLANDI');
    return;
  }

  // URL/IP/Hash/File scan
  const s = d.attrs?.stats || {};
  const mal = s.malicious||0, sus = s.suspicious||0;
  const total = Object.values(s).reduce((a,b)=>a+b,0);
  const risk = Math.round(((mal+sus*.5)/Math.max(total,1))*100);
  const verdictColor = mal>0?'#ff2244':sus>0?'#ffcc00':'#00ff88';
  const verdictText = mal>0?'XAVFLI':sus>0?'SHUBHALI':'XAVFSIZ';

  const summaryHTML = `<div class="stats-row">
    <div class="stat-card"><div class="stat-label">JAMI ENGINE</div><div class="stat-val" style="color:#0af">${total}</div></div>
    <div class="stat-card"><div class="stat-label">XAVFLI</div><div class="stat-val" style="color:${mal>0?'#ff2244':'#3a6a4a'}">${mal}</div></div>
    <div class="stat-card"><div class="stat-label">SHUBHALI</div><div class="stat-val" style="color:${sus>0?'#ffcc00':'#3a6a4a'}">${sus}</div></div>
    <div class="stat-card"><div class="stat-label">XAVFSIZ</div><div class="stat-val" style="color:#00ff88">${(s.harmless||0)+(s.undetected||0)}</div></div>
  </div>`;

  const engs = Object.entries(d.attrs?.results||{}).slice(0,72);
  const findingsHTML = `<div class="section">
    <div class="section-head">// ENGINE NATIJALARI <span class="section-count">${engs.length} TA</span></div>
    <table>
      <tr><th>ENGINE</th><th>NATIJA</th><th>KATEGORIYA</th></tr>
      ${engs.map(([e,r])=>{
        const cat = r.category||'';
        const sc = cat==='malicious'?'tag-bad':cat==='suspicious'?'tag-warn':cat==='harmless'?'tag-ok':'';
        return `<tr><td style="color:#5a8a6a">${e}</td><td>${r.result||'—'}</td><td class="${sc}">${cat.toUpperCase()||'—'}</td></tr>`;
      }).join('')}
    </table>
  </div>`;

  const metaHTML = `<div class="section" style="margin-top:18px">
    <div class="section-head">// MAQSAD MA'LUMOTLARI</div>
    <div style="padding:16px">
      <div class="meta-row"><span class="mk">Maqsad</span><span class="mv" style="word-break:break-all">${d.meta?.value||'—'}</span></div>
      <div class="meta-row"><span class="mk">Tur</span><span class="mv">${(d.meta?.type||'').toUpperCase()}</span></div>
    </div>
  </div>`;

  const html = buildHTML((d.meta?.type||'').toUpperCase()+' SKAN', verdictColor, verdictText, risk, summaryHTML, findingsHTML, '', metaHTML);
  const a = document.createElement('a');
  a.href = 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
  a.download = 'threatscan-report-' + Date.now() + '.html';
  a.click();
  toast('[DL] HTML YUKLANDI');
}


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
  const d = window._data;
  const line = '═'.repeat(44);
  const thin = '─'.repeat(44);

  if (d.meta?.type === 'text') {
    const malF = d.findings?.filter(f => f.status === 'bad').length || 0;
    const warnF = d.findings?.filter(f => f.status === 'warn').length || 0;
    const risk = d.totalRisk || 0;
    const verdict = malF > 0 ? 'XAVFLI' : warnF > 0 ? 'SHUBHALI' : 'XAVFSIZ';
    const riskLabel = risk > 60 ? 'YUQORI XAVF' : risk > 20 ? "O'RTA XAVF" : 'QUYI XAVF';

    const findingLines = (d.findings || []).map(f => {
      const s = f.status === 'bad' ? 'XAVFLI' : f.status === 'warn' ? 'SHUBHALI' : f.status === 'info' ? "MA'LUMOT" : 'XAVFSIZ';
      return `  [${f.type}] ${f.value}\n        ${f.detail || ''} | ${s}`;
    });

    const aiLines = d.aiResult ? [
      '',
      '── GEMINI AI TAHLIL ' + thin.slice(20),
      `  Daraja    : ${d.aiResult.xavf_darajasi || '—'}`,
      `  Matn turi : ${d.aiResult.matn_turi || '—'}`,
      `  Til       : ${d.aiResult.til || '—'}`,
      `  Xulosa    : ${d.aiResult.xulosa || '—'}`,
      d.aiResult.sabab?.length ? `  Sabab     : ${d.aiResult.sabab.join(' | ')}` : '',
      d.aiResult.tavsiya ? `  Tavsiya   : ${d.aiResult.tavsiya}` : '',
    ].filter(Boolean) : ['', '── AI TAHLIL: mavjud emas (Gemini ulanmagan)'];

    navigator.clipboard.writeText([
      line,
      '   THREATSCAN PRO — MATN TAHLIL HISOBOT',
      line,
      `  Sana     : ${new Date(d.ts).toLocaleString()}`,
      `  Xavf     : ${risk}% — ${riskLabel}`,
      `  Natija   : ${verdict}`,
      '',
      '── STATISTIKA ' + thin.slice(14),
      `  Xavfli element   : ${malF}`,
      `  Shubhali element : ${warnF}`,
      `  Jami topildi     : ${d.findings?.length || 0}`,
      ...aiLines,
      '',
      '── TOPILGAN ELEMENTLAR ' + thin.slice(23),
      ...(findingLines.length ? findingLines : ['  Hech narsa topilmadi']),
      '',
      line,
      `  YAKUNIY NATIJA: ${verdict}`,
      line,
      '  ThreatScan Pro · threatscan.app',
    ].join('\n')).then(() => toast('[OK] NUSXALANDI'));
    return;
  }

  const s = d.attrs?.stats || {};
  const mal = s.malicious || 0, sus = s.suspicious || 0;
  const total = Object.values(s).reduce((a, b) => a + b, 0);
  const risk = Math.round(((mal + sus * .5) / Math.max(total, 1)) * 100);
  const verdict = mal > 0 ? 'XAVFLI' : sus > 0 ? 'SHUBHALI' : 'XAVFSIZ';
  navigator.clipboard.writeText([
    line,
    '   THREATSCAN PRO — TAHLIL HISOBOT',
    line,
    `  Sana    : ${new Date(d.ts).toLocaleString()}`,
    `  Maqsad  : ${d.meta?.value}`,
    `  Tur     : ${d.meta?.type?.toUpperCase()}`,
    '',
    '── NATIJALAR ' + thin.slice(13),
    `  Xavfli   : ${mal}`,
    `  Shubhali : ${sus}`,
    `  Jami     : ${total}`,
    `  Xavf     : ${risk}%`,
    '',
    line,
    `  YAKUNIY NATIJA: ${verdict}`,
    line,
    '  ThreatScan Pro · threatscan.app',
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
