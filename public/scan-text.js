// ============================================================
// scan-text.js — Matn tahlil moduli
// URL, IP, telefon, koordinata, username ajratib tekshiradi
// ============================================================

// ── Regex patterns ──────────────────────────────────────────

const PATTERNS = {
  url:      /https?:\/\/[^\s<>"{}|\\^`[\]]{4,}/gi,
  ip:       /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
  coord:    /[-+]?\d{1,3}\.\d{4,},\s*[-+]?\d{1,3}\.\d{4,}/g,
  phone:    /(?:\+?998|8)[\s\-]?\d{2}[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}/g,
  username: /@[\w\d_]{3,32}/g,
  hash:     /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g,
  domain:   /(?<![/@])\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|uz|info|online|xyz|site|top|tk|ml|ga|cf)\b/gi,
};

// Fishing/scam kalit so'zlar
const SUSPICIOUS_WORDS = [
  'nasiya', 'kredit', 'bonus', 'bepul', 'sovg\'a', 'mukofot',
  'parol', 'login', 'bank', 'karta', 'plastik', 'password',
  'verify', 'tasdiqlang', 'urgent', 'winning', 'lottery',
  'hujjat', 'pasport', 'passport', 'click here', 'limited time',
  'free money', 'prize', 'congratulations', 'account suspended',
];

// ── Matndan elementlarni ajratish ──────────────────────────

function extractIndicators(text) {
  const found = {
    urls:      [...new Set(text.match(PATTERNS.url) || [])].slice(0, 5),
    ips:       [...new Set(text.match(PATTERNS.ip) || [])].slice(0, 5),
    coords:    [...new Set(text.match(PATTERNS.coord) || [])].slice(0, 5),
    phones:    [...new Set(text.match(PATTERNS.phone) || [])].slice(0, 5),
    usernames: [...new Set(text.match(PATTERNS.username) || [])].slice(0, 10),
    hashes:    [...new Set(text.match(PATTERNS.hash) || [])].slice(0, 3),
    domains: [...new Set(text.match(PATTERNS.domain) || [])].slice(0, 5),
  };

  // Shubhali so'zlarni tekshirish
  const lowerText = text.toLowerCase();
  const suspWords = SUSPICIOUS_WORDS.filter(w => lowerText.includes(w.toLowerCase()));

  return { found, suspWords };
}

// ── Matn tahlil asosiy funksiya ─────────────────────────────

async function scanText(text) {
  const { found, suspWords } = extractIndicators(text);
  const findings = [];
  let totalRisk = 0;

  // Shubhali so'zlardan boshlang'ich risk
  if (suspWords.length >= 3) totalRisk = Math.max(totalRisk, 30);
  if (suspWords.length >= 5) totalRisk = Math.max(totalRisk, 50);

  document.getElementById('scanSub').textContent = 'Indikatorlar ajratildi, tekshirilmoqda...';

  // ── URLlarni tekshirish (VT + URLhaus) ──
  for (const url of found.urls) {
    document.getElementById('scanSub').textContent = `URL tekshirilmoqda: ${url.slice(0, 40)}...`;
    try {
      const form = new URLSearchParams();
      form.append('url', url);
      const sub = await vtFetch('/urls', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form.toString()
      });
      const res = await poll(sub.data.id);
      const s = res.data.attributes.stats || {};
      const mal = s.malicious || 0, sus = s.suspicious || 0;
      const risk = Math.round(((mal + sus * .5) / Math.max(Object.values(s).reduce((a, b) => a + b, 0), 1)) * 100);
      totalRisk = Math.max(totalRisk, risk);
      findings.push({ type: 'URL', value: url, mal, sus, risk, status: mal > 0 ? 'bad' : sus > 0 ? 'warn' : 'ok', detail: mal > 0 ? `${mal} engine xavfli dedi` : 'Xavfsiz' });
    } catch (e) {
      // URLhaus fallback
      try {
        const uh = await urlhausFetch(url);
        const isBad = uh.query_status === 'is_phishing' || uh.query_status === 'is_malware';
        if (isBad) totalRisk = Math.max(totalRisk, 80);
        findings.push({ type: 'URL', value: url, mal: isBad ? 1 : 0, sus: 0, risk: isBad ? 80 : 0, status: isBad ? 'bad' : 'ok', detail: uh.query_status || 'URLhaus' });
      } catch (e2) {
        findings.push({ type: 'URL', value: url, mal: 0, sus: 0, risk: 0, status: 'na', detail: 'Tekshirib bo\'lmadi' });
      }
    }
  }

  // ── IPlarni tekshirish (AbuseIPDB) ──
  for (const ip of found.ips) {
    // Private IP larni o'tkazib yuborish
    if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/.test(ip)) {
      findings.push({ type: 'IP', value: ip, mal: 0, sus: 0, risk: 0, status: 'info', detail: 'Lokal IP' });
      continue;
    }
    document.getElementById('scanSub').textContent = `IP tekshirilmoqda: ${ip}`;
    try {
      const res = await abuseFetch('/check?ipAddress=' + encodeURIComponent(ip) + '&maxAgeInDays=90');
      const score = res.data?.abuseConfidenceScore || 0;
      const country = res.data?.countryCode || '';
      const isp = res.data?.isp || '';
      totalRisk = Math.max(totalRisk, score);
      findings.push({
        type: 'IP', value: ip,
        mal: score > 50 ? 1 : 0, sus: 0, risk: score,
        status: score > 50 ? 'bad' : score > 10 ? 'warn' : 'ok',
        detail: `${score}% xavf · ${country} · ${isp}`.slice(0, 50)
      });
    } catch (e) {
      findings.push({ type: 'IP', value: ip, mal: 0, sus: 0, risk: 0, status: 'na', detail: 'Tekshirib bo\'lmadi' });
    }
  }

  // ── Hashlarni tekshirish (VT + MalwareBazaar) ──
  for (const hash of found.hashes) {
    document.getElementById('scanSub').textContent = `Hash tekshirilmoqda: ${hash.slice(0, 16)}...`;
    try {
      const [vtRes, mbRes] = await Promise.allSettled([
        vtFetch('/files/' + hash),
        mbFetch(hash)
      ]);
      const vtAttrs = vtRes.status === 'fulfilled' ? vtRes.value?.data?.attributes : null;
      const mbOk = mbRes.status === 'fulfilled' && mbRes.value?.query_status === 'ok';
      const mal = vtAttrs?.last_analysis_stats?.malicious || 0;
      const risk = mal > 0 ? Math.min(100, mal * 2) : mbOk ? 70 : 0;
      totalRisk = Math.max(totalRisk, risk);
      findings.push({
        type: 'HASH', value: hash.slice(0, 20) + '…',
        mal, sus: 0, risk,
        status: mal > 0 || mbOk ? 'bad' : 'ok',
        detail: mal > 0 ? `VT: ${mal} tahdid` : mbOk ? 'MalwareBazaar: topildi' : 'Xavfsiz'
      });
    } catch (e) {
      findings.push({ type: 'HASH', value: hash.slice(0, 20) + '…', mal: 0, sus: 0, risk: 0, status: 'na', detail: 'Topilmadi' });
    }
  }

  // ── Koordinatalar (tekshirib bo'lmaydi, ko'rsatish) ──
  for (const coord of found.coords) {
    const [lat, lon] = coord.split(',').map(s => parseFloat(s.trim()));
    const mapsUrl = `https://maps.google.com/maps?q=${lat},${lon}`;
    findings.push({
      type: 'KOORDINATA', value: coord,
      mal: 0, sus: 0, risk: 0,
      status: 'info',
      detail: `<a href="${mapsUrl}" target="_blank" style="color:var(--blue)">Xaritada ko'rish ↗</a>`
    });
  }

  // ── Telefon raqamlar ──
  for (const phone of found.phones) {
    findings.push({
      type: 'TELEFON', value: phone.trim(),
      mal: 0, sus: 0, risk: 0,
      status: 'info', detail: 'O\'zbekiston raqami'
    });
  }

  // ── Telegram usernames ──
  for (const u of found.usernames) {
    findings.push({
      type: 'USERNAME', value: u,
      mal: 0, sus: 0, risk: 0,
      status: 'info',
      detail: `<a href="https://t.me/${u.slice(1)}" target="_blank" style="color:var(--blue)">Telegram ↗</a>`
    });
  }

  // ── Shubhali so'zlar ──
  if (suspWords.length > 0) {
    findings.push({
      type: 'KALIT SO\'Z', value: suspWords.slice(0, 5).join(', '),
      mal: 0, sus: suspWords.length, risk: Math.min(suspWords.length * 10, 60),
      status: suspWords.length >= 3 ? 'warn' : 'info',
      detail: `${suspWords.length} ta shubhali so'z topildi`
    });
    totalRisk = Math.max(totalRisk, Math.min(suspWords.length * 10, 60));
  }

  // ── Gemini AI tahlil ──
  let aiResult = null;
  try {
    document.getElementById('scanSub').textContent = 'AI matn tahlili qilinmoqda...';
    aiResult = await geminiAnalyze(text, found);
    if (aiResult && aiResult.xavf_foiz) {
      totalRisk = Math.max(totalRisk, aiResult.xavf_foiz);
    }
  } catch (e) {
    console.warn('Gemini xatosi:', e.message);
  }

  stopTimer();
  renderText(text, findings, totalRisk, found, suspWords, aiResult);
}

// ── Gemini AI funksiya ──────────────────────────────────────

async function geminiAnalyze(text, found) {
  const res = await fetch('/api/gemini/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, indicators: found })
  });
  if (!res.ok) throw new Error('Gemini HTTP ' + res.status);
  const data = await res.json();
  const raw = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
  const clean = raw.replace(/```json\n?|```\n?/g, '').trim();
  const jsonMatch = clean.match(/\{[\s\S]*\}/);
  if (!jsonMatch) throw new Error('JSON topilmadi');
  return JSON.parse(jsonMatch[0]);
}

// ── renderText ──────────────────────────────────────────────

function renderText(text, findings, totalRisk, found, suspWords, aiResult) {
  window._data = { text, findings, totalRisk, aiResult, meta: { type: 'text', value: text.slice(0, 60) + '…' }, ts: new Date().toISOString() };

  const malF = findings.filter(f => f.status === 'bad');
  const warnF = findings.filter(f => f.status === 'warn');
  const cleanF = findings.filter(f => f.status === 'ok');

  // Sources summary
  document.getElementById('sourcesRow').innerHTML = [
    { name: 'JAMI ELEMENT', val: findings.length + ' TA', cls: malF.length > 0 ? 'bad' : warnF.length > 0 ? 'warn' : findings.length > 0 ? 'ok' : 'na' },
    { name: 'XAVFLI', val: malF.length + ' TA', cls: malF.length > 0 ? 'bad' : 'ok' },
    { name: 'SHUBHALI', val: warnF.length + ' TA', cls: warnF.length > 0 ? 'warn' : 'ok' },
    { name: 'KALIT SO\'Z', val: (suspWords?.length || 0) + ' TA', cls: (suspWords?.length || 0) >= 3 ? 'warn' : 'ok' },
  ].map(s => `<div class="source-badge">
    <div class="source-dot ${s.cls}"></div>
    <span class="source-name">${s.name}</span>
    <span class="source-val">${s.val}</span>
  </div>`).join('');

  document.getElementById('sMal').textContent = malF.length;
  document.getElementById('sSus').textContent = warnF.length;
  document.getElementById('sClean').textContent = cleanF.length;
  document.getElementById('sTotal').textContent = findings.length;

  // Verdict
  let vc, vs, vt, vd, vi;
  if (malF.length > 0) {
    vc = 'malicious'; vs = 'XAVFLI MATN'; vt = 'TAHDID ANIQLANDI';
    vd = `${malF.length} ta xavfli element topildi`; vi = '⛔';
  } else if (warnF.length > 0 || (suspWords?.length || 0) >= 3) {
    vc = 'suspicious'; vs = 'SHUBHALI MATN'; vt = "EHTIYOT BO'LING";
    vd = `${warnF.length} shubhali · ${suspWords?.length || 0} kalit so'z`; vi = '⚠';
  } else if (totalRisk > 60) {
    vc = 'malicious'; vs = 'XAVFLI MATN'; vt = 'YUQORI XAVF';
    vd = `Xavf darajasi ${totalRisk}%`; vi = '⛔';
  } else if (totalRisk > 20) {
    vc = 'suspicious'; vs = 'SHUBHALI MATN'; vt = "EHTIYOT BO'LING";
    vd = `Xavf darajasi ${totalRisk}%`; vi = '⚠';
  } else if (findings.length > 0) {
    vc = 'clean'; vs = 'XAVFSIZ'; vt = "TAHDID YO'Q";
    vd = `${findings.length} ta element tekshirildi`; vi = '✓';
  } else {
    vc = 'unknown'; vs = 'NOANIQ'; vt = 'ELEMENT TOPILMADI';
    vd = 'Tekshiriladigan narsa yo\'q'; vi = '?';
  }

  document.getElementById('verdictBox').className = 'verdict ' + vc;
  const vEl = document.getElementById('vTitle');
  vEl.textContent = vt; vEl.setAttribute('data-text', vt);
  document.getElementById('vStatus').textContent = vs;
  document.getElementById('vDesc').textContent = vd;
  document.getElementById('vIcon').textContent = vi;
  document.getElementById('vPct').textContent = totalRisk + '%';

  const bf = document.getElementById('barFill');
  bf.style.width = totalRisk + '%';
  bf.style.background = totalRisk > 60
    ? 'linear-gradient(90deg,var(--red2),var(--red))'
    : totalRisk > 20
      ? 'linear-gradient(90deg,#aa8800,var(--yellow))'
      : 'linear-gradient(90deg,var(--green2),var(--green))';
  const riskLabelEl = document.getElementById('riskLabel');
  riskLabelEl.textContent = totalRisk + '% — ' +
    (totalRisk > 60 ? 'YUQORI XAVF' : totalRisk > 20 ? "O'RTA XAVF" : 'QUYI XAVF');
  riskLabelEl.style.color = totalRisk > 60 ? 'var(--red)' : totalRisk > 20 ? 'var(--yellow)' : 'var(--green)';

  document.getElementById('catsSection').style.display = 'none';

  // Meta — topilgan elementlar soni
  const counts = [
    ['URL', found?.urls?.length || 0],
    ['IP manzil', found?.ips?.length || 0],
    ['Koordinata', found?.coords?.length || 0],
    ['Telefon', found?.phones?.length || 0],
    ['Username', found?.usernames?.length || 0],
    ['Hash', found?.hashes?.length || 0],
    ["Shubhali so'z", suspWords?.length || 0],
  ].filter(([, v]) => v > 0);

  document.getElementById('metaRows').innerHTML = counts.length
    ? counts.map(([k, v]) => `<div class="meta-row"><span class="mk">${k}</span><span class="mv">${v} ta topildi</span></div>`).join('')
    : '<div style="padding:14px;font-size:11px;color:var(--text3)">Hech narsa topilmadi</div>';

  // Tech — matn statistika + AI xulosa
  const words = text.split(/\s+/).length;
  const chars = text.length;
  const links = found?.urls?.length || 0;

  let techHTML = [
    ['Belgilar', chars],
    ['So\'zlar', words],
    ['Linklar', links],
    ['Xavf darajasi', totalRisk + '%'],
  ].map(([k, v]) => `<div class="meta-row"><span class="mk">${k}</span><span class="mv">${v}</span></div>`).join('');

  // AI tahlil bloki
  if (aiResult) {
    const aiColor = aiResult.xavf_darajasi === 'XAVFLI' ? 'var(--red)' :
                    aiResult.xavf_darajasi === 'SHUBHALI' ? 'var(--yellow)' : 'var(--green)';
    techHTML += `
      <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border)">
        <div style="font-size:10px;color:var(--text3);letter-spacing:1px;margin-bottom:8px">// GEMINI AI TAHLIL</div>
        <div style="font-size:11px;color:${aiColor};font-weight:600;margin-bottom:6px">
          ${aiResult.xavf_darajasi || '—'} · ${aiResult.matn_turi || '—'}
        </div>
        <div style="font-size:11px;color:var(--text2);line-height:1.6;margin-bottom:8px">
          ${aiResult.xulosa || '—'}
        </div>
        ${aiResult.sabab?.length ? `<div style="font-size:10px;color:var(--text3);margin-bottom:4px">Sabab:</div>
        <div style="font-size:11px;color:var(--yellow)">${aiResult.sabab.join(' · ')}</div>` : ''}
        ${aiResult.tavsiya ? `<div style="font-size:10px;color:var(--text3);margin-top:6px;margin-bottom:4px">Tavsiya:</div>
        <div style="font-size:11px;color:var(--green)">${aiResult.tavsiya}</div>` : ''}
      </div>`;
  }

  document.getElementById('techRows').innerHTML = techHTML;

  // Findings jadval
  document.getElementById('engCount').textContent = findings.length + ' TOPILDI';
  document.getElementById('engGrid').innerHTML = findings.length
    ? findings.map(f => {
      const statusColor = f.status === 'bad' ? 'bad' : f.status === 'warn' ? 'sus' : 'ok';
      const statusText = f.status === 'bad' ? 'XAVFLI' : f.status === 'warn' ? 'SHUBHALI' : f.status === 'info' ? "MA'LUMOT" : 'XAVFSIZ';
      return `<div class="eng-row ${f.status === 'bad' ? 'bad' : f.status === 'warn' ? 'sus' : ''}">
        <span class="en" style="flex-direction:column;align-items:flex-start">
          <span style="color:var(--text3);font-size:10px">[${f.type}]</span>
          <span style="color:var(--text2)">${f.value.length > 32 ? f.value.slice(0, 32) + '…' : f.value}</span>
          <span style="color:var(--text3);font-size:10px">${f.detail || ''}</span>
        </span>
        <span class="er ${statusColor}" style="white-space:nowrap">${statusText}</span>
      </div>`;
    }).join('')
    : '<div style="padding:20px;font-size:12px;color:var(--text3);text-align:center">Element topilmadi</div>';

  document.getElementById('results').style.display = 'block';
  document.getElementById('results').classList.add('show');
  document.getElementById('scanOverlay').classList.remove('show');
  document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}