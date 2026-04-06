// ============================================================
// scan-render.js — render va renderIP funksiyalari
// ============================================================

function showResults() {
  document.getElementById('results').style.display = 'block';
  document.getElementById('results').classList.add('show');
  document.getElementById('scanOverlay').classList.remove('show');
  document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function setVerdict(vc, vs, vt, vd, vi) {
  document.getElementById('verdictBox').className = 'verdict ' + vc;
  document.getElementById('vStatus').textContent = vs;
  const el = document.getElementById('vTitle');
  el.textContent = vt;
  el.setAttribute('data-text', vt);
  document.getElementById('vDesc').textContent = vd;
  document.getElementById('vIcon').textContent = vi;
}

function setRiskBar(risk) {
  document.getElementById('vPct').textContent = risk + '%';
  const bf = document.getElementById('barFill');
  bf.style.width = risk + '%';
  bf.style.background = risk > 60
    ? 'linear-gradient(90deg,var(--red2),var(--red))'
    : risk > 20
      ? 'linear-gradient(90deg,#aa8800,var(--yellow))'
      : 'linear-gradient(90deg,var(--green2),var(--green))';
  document.getElementById('riskLabel').textContent = risk + '% — ' +
    (risk > 60 ? 'YUQORI XAVF' : risk > 20 ? "O'RTA XAVF" : 'QUYI XAVF');
}

function metaRow(k, v) {
  return `<div class="meta-row"><span class="mk">${k}</span><span class="mv">${v}</span></div>`;
}

// ── render (URL / fayl / hash) ──────────────────────────────

function render(attrs, details, meta, extra = {}) {
  // Normalize stats/results (hash uchun)
  if (!attrs.stats && attrs.last_analysis_stats) attrs.stats = attrs.last_analysis_stats;
  if (!attrs.results && attrs.last_analysis_results) attrs.results = attrs.last_analysis_results;

  window._data = { attrs, details, meta, extra, ts: new Date().toISOString() };

  const s = attrs?.stats || {};
  const mal = s.malicious || 0, sus = s.suspicious || 0, undet = s.undetected || 0;
  const total = Object.values(s).reduce((a, b) => a + b, 0);
  const risk = Math.round(((mal + sus * .5) / Math.max(total, 1)) * 100);

  // Sources row
  const sources = [
    { name: 'VIRUSTOTAL', val: mal > 0 ? `${mal} TAHDID` : total > 0 ? 'XAVFSIZ' : '—', cls: mal > 0 ? 'bad' : total > 0 ? 'ok' : 'na' },
  ];
  if (extra.urlhaus) {
    const uh = extra.urlhaus;
    sources.push({
      name: 'URLHAUS',
      val: uh.query_status === 'is_phishing' || uh.query_status === 'is_malware' ? 'XAVFLI' : uh.query_status === 'no_results' ? 'TOPILMADI' : 'XAVFSIZ',
      cls: (uh.query_status === 'is_phishing' || uh.query_status === 'is_malware') ? 'bad' : 'ok'
    });
  }
  if (extra.urlscan?.verdicts?.overall) {
    const v = extra.urlscan.verdicts.overall;
    sources.push({ name: 'URLSCAN', val: v.malicious ? 'XAVFLI' : v.score > 0 ? 'SHUBHALI' : 'XAVFSIZ', cls: v.malicious ? 'bad' : v.score > 0 ? 'warn' : 'ok' });
  }
  if (extra.malwarebazaar) {
    const mb = extra.malwarebazaar;
    sources.push({ name: 'MALWAREBAZAAR', val: mb.query_status === 'ok' ? 'BAZADA BOR' : 'TOPILMADI', cls: mb.query_status === 'ok' ? 'bad' : 'na' });
  }

  document.getElementById('sourcesRow').innerHTML = sources.map(s =>
    `<div class="source-badge">
      <div class="source-dot ${s.cls}"></div>
      <span class="source-name">${s.name}</span>
      <span class="source-val">${s.val}</span>
    </div>`).join('');

  // Stats
  document.getElementById('sMal').textContent = mal;
  document.getElementById('sSus').textContent = sus;
  document.getElementById('sClean').textContent = undet;
  document.getElementById('sTotal').textContent = total;

  // Verdict
  let vc, vs, vt, vd, vi;
  if (mal >= 10) { vc = 'malicious'; vs = 'KRITIK TAHDID'; vt = 'ZARARLI DASTUR'; vd = `${mal} ta engine tahdid aniqladi`; vi = '☠'; }
  else if (mal > 0) { vc = 'malicious'; vs = 'TAHDID ANIQLANDI'; vt = 'XAVFLI'; vd = `${mal} malicious · ${sus} suspicious`; vi = '⛔'; }
  else if (sus > 3) { vc = 'suspicious'; vs = 'SHUBHALI FAOLIYAT'; vt = 'TEKSHIRING'; vd = `${sus} ta engine shubhali dedi`; vi = '⚠'; }
  else if (sus > 0) { vc = 'suspicious'; vs = "EHTIYOT BO'LING"; vt = 'SHUBHALI'; vd = `${sus} ta shubhali signal`; vi = '⚠'; }
  else if (total > 0) { vc = 'clean'; vs = 'XAVFSIZ'; vt = "TAHDID YO'Q"; vd = `${total} ta engine — barchasi xavfsiz`; vi = '✓'; }
  else { vc = 'unknown'; vs = 'NOANIQ'; vt = "MA'LUMOT YO'Q"; vd = 'Tahlil qilinmagan yoki yangi'; vi = '?'; }

  setVerdict(vc, vs, vt, vd, vi);
  setRiskBar(risk);

  // Categories
  const cats = { ...(attrs?.categories || {}), ...(details?.categories || {}) };
  const catArr = [...new Set(Object.values(cats))].slice(0, 12);
  if (catArr.length) {
    document.getElementById('catsSection').style.display = 'block';
    const dw = ['malware', 'phish', 'malicious', 'spam', 'exploit', 'trojan', 'ransomware'];
    const ww = ['suspicious', 'adware', 'pua', 'greyware'];
    document.getElementById('catsBox').innerHTML = catArr.map(c => {
      const cl = dw.some(w => c.toLowerCase().includes(w)) ? 'danger' : ww.some(w => c.toLowerCase().includes(w)) ? 'warn' : 'info';
      return `<span class="cat ${cl}">${c}</span>`;
    }).join('');
  } else {
    document.getElementById('catsSection').style.display = 'none';
  }

  // Meta
  const mi = [];
  if (meta.value) mi.push(['Maqsad', meta.value.length > 55 ? meta.value.slice(0, 55) + '…' : meta.value]);
  mi.push(['Tur', meta.type.toUpperCase()]);
  if (attrs?.last_analysis_date) mi.push(['Oxirgi skan', new Date(attrs.last_analysis_date * 1000).toLocaleDateString()]);
  if (attrs?.times_submitted) mi.push(['Yuborilgan', attrs.times_submitted + ' marta']);
  if (attrs?.reputation !== undefined) mi.push(['Reputatsiya', (attrs.reputation > 0 ? '+' : '') + attrs.reputation]);
  if (attrs?.tld) mi.push(['TLD', '.' + attrs.tld]);
  if (attrs?.country) mi.push(['Mamlakat', attrs.country]);
  document.getElementById('metaRows').innerHTML = mi.map(([k, v]) => metaRow(k, v)).join('');

  // Tech
  const ti = [];
  if (attrs?.sha256) ti.push(['SHA256', attrs.sha256.slice(0, 18) + '…']);
  if (attrs?.md5) ti.push(['MD5', attrs.md5]);
  if (attrs?.size) ti.push(['Hajm', fmtSize(attrs.size)]);
  if (attrs?.type_description) ti.push(['Fayl turi', attrs.type_description]);
  if (attrs?.magic) ti.push(['Magic', attrs.magic.slice(0, 30)]);
  // MalwareBazaar extra
  if (extra.malwarebazaar?.data?.[0]) {
    const mb = extra.malwarebazaar.data[0];
    if (mb.file_type) ti.push(['MB Tur', mb.file_type]);
    if (mb.signature) ti.push(['Signature', mb.signature]);
    if (mb.tags) ti.push(['MB Tags', mb.tags.slice(0, 3).join(', ')]);
  }
  document.getElementById('techRows').innerHTML = ti.length
    ? ti.map(([k, v]) => metaRow(k, v)).join('')
    : '<div style="padding:14px;font-size:11px;color:var(--text3)">Ma\'lumot yo\'q</div>';

  // Engines
  const res = attrs?.results || {};
  const engs = Object.entries(res).sort((a, b) => {
    const r = x => x.category === 'malicious' ? 0 : x.category === 'suspicious' ? 1 : 2;
    return r(a[1]) - r(b[1]);
  });
  document.getElementById('engCount').textContent = engs.length + ' ENGINE';
  document.getElementById('engGrid').innerHTML = engs.map(([e, r]) => {
    const bad = r.category === 'malicious', sus2 = r.category === 'suspicious';
    return `<div class="eng-row ${bad ? 'bad' : sus2 ? 'sus' : ''}">
      <span class="en">${e}</span>
      <span class="er ${bad ? 'bad' : sus2 ? 'sus' : 'ok'}">${r.result || (r.category === 'undetected' ? 'CLEAN' : r.category || '—')}</span>
    </div>`;
  }).join('');

  showResults();
}

// ── renderIP ────────────────────────────────────────────────

function renderIP(ip, vtData, abuseData, threatfoxData) {
  window._data = { vtData, abuseData, threatfoxData, meta: { type: 'ip', value: ip }, ts: new Date().toISOString() };

  const aScore = abuseData?.abuseConfidenceScore || 0;
  const reports = abuseData?.totalReports || 0;
  const vtMal = vtData?.last_analysis_stats?.malicious || 0;
  const vtTotal = Object.values(vtData?.last_analysis_stats || {}).reduce((a, b) => a + b, 0);
  const tfHits = threatfoxData?.data?.length || 0;
  const risk = Math.round(Math.max(aScore, (vtMal / Math.max(vtTotal, 1)) * 100, tfHits > 0 ? 60 : 0));

  // Sources
  const sources = [
    { name: 'ABUSEIPDB', val: aScore > 50 ? `${aScore}% XAVFLI` : reports > 0 ? `${reports} REPORT` : 'XAVFSIZ', cls: aScore > 50 ? 'bad' : reports > 0 ? 'warn' : 'ok' },
    { name: 'VIRUSTOTAL', val: vtMal > 0 ? `${vtMal} TAHDID` : vtTotal > 0 ? 'XAVFSIZ' : '—', cls: vtMal > 0 ? 'bad' : vtTotal > 0 ? 'ok' : 'na' },
    { name: 'THREATFOX', val: tfHits > 0 ? `${tfHits} IoC` : 'TOPILMADI', cls: tfHits > 0 ? 'bad' : 'ok' },
  ];
  document.getElementById('sourcesRow').innerHTML = sources.map(s =>
    `<div class="source-badge">
      <div class="source-dot ${s.cls}"></div>
      <span class="source-name">${s.name}</span>
      <span class="source-val">${s.val}</span>
    </div>`).join('');

  document.getElementById('sMal').textContent = vtMal;
  document.getElementById('sSus').textContent = reports;
  document.getElementById('sClean').textContent = vtTotal - vtMal;
  document.getElementById('sTotal').textContent = vtTotal;

  let vc, vs, vt, vd, vi;
  if (aScore > 75 || vtMal > 5 || tfHits > 0) { vc = 'malicious'; vs = 'XAVFLI IP'; vt = 'BLOKLANG'; vd = `AbuseIPDB: ${aScore}% · ThreatFox: ${tfHits} IoC`; vi = '⛔'; }
  else if (aScore > 25 || reports > 0) { vc = 'suspicious'; vs = 'SHUBHALI IP'; vt = 'EHTIYOT'; vd = `${reports} ta shikoyat topildi`; vi = '⚠'; }
  else { vc = 'clean'; vs = 'XAVFSIZ IP'; vt = 'NORMAL'; vd = 'Shikoyat topilmadi'; vi = '✓'; }

  setVerdict(vc, vs, vt, vd, vi);
  setRiskBar(risk);
  document.getElementById('catsSection').style.display = 'none';

  const mi = [['IP Manzil', ip]];
  if (abuseData?.countryCode) mi.push(['Mamlakat', abuseData.countryCode]);
  if (abuseData?.isp) mi.push(['ISP', abuseData.isp]);
  if (abuseData?.domain) mi.push(['Domain', abuseData.domain]);
  if (abuseData?.usageType) mi.push(['Tur', abuseData.usageType]);
  if (abuseData?.lastReportedAt) mi.push(['Oxirgi shikoyat', new Date(abuseData.lastReportedAt).toLocaleDateString()]);
  document.getElementById('metaRows').innerHTML = mi.map(([k, v]) => metaRow(k, v || '—')).join('');

  const ti = [
    ['Confidence', aScore + '%'],
    ['Jami shikoyat', reports],
    ['VT malicious', vtMal],
    ['VT total', vtTotal],
    ['ThreatFox IoC', tfHits],
  ];
  if (threatfoxData?.data?.[0]) {
    const tf = threatfoxData.data[0];
    if (tf.malware_printable) ti.push(['Malware', tf.malware_printable]);
    if (tf.threat_type) ti.push(['Tahdid turi', tf.threat_type]);
  }
  document.getElementById('techRows').innerHTML = ti.map(([k, v]) => metaRow(k, v)).join('');

  const res = vtData?.last_analysis_results || {};
  const engs = Object.entries(res).filter(([, r]) => r.category !== 'undetected').sort((a, b) => a[1].category === 'malicious' ? -1 : 1);
  document.getElementById('engCount').textContent = Object.keys(res).length + ' ENGINE';
  document.getElementById('engGrid').innerHTML = engs.length
    ? engs.map(([e, r]) => `
      <div class="eng-row ${r.category === 'malicious' ? 'bad' : 'sus'}">
        <span class="en">${e}</span>
        <span class="er ${r.category === 'malicious' ? 'bad' : 'sus'}">${r.result || r.category}</span>
      </div>`).join('')
    : '<div style="padding:20px;font-size:12px;color:var(--text3);text-align:center">Tahdid topilmadi</div>';

  showResults();
}
