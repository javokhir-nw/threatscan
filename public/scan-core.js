// ============================================================
// scan-core.js — API fetch funksiyalari va asosiy scan
// ============================================================

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── API fetch wrappers ──────────────────────────────────────

async function vtFetch(path, opts = {}) {
  const res = await fetch('/api/vt' + path, { ...opts });
  if (!res.ok) {
    const e = await res.json().catch(() => ({}));
    throw new Error(e.error?.message || 'VT HTTP ' + res.status);
  }
  return res.json();
}

async function abuseFetch(path) {
  const res = await fetch('/api/abuse' + path);
  if (!res.ok) throw new Error('AbuseIPDB HTTP ' + res.status);
  return res.json();
}

async function urlscanFetch(path, opts = {}) {
  const res = await fetch('/api/urlscan' + path, { ...opts });
  if (!res.ok) throw new Error('URLScan HTTP ' + res.status);
  return res.json();
}

// MalwareBazaar — API keysiz
async function mbFetch(hash) {
  const res = await fetch('https://mb-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'query=get_info&hash=' + hash
  });
  if (!res.ok) throw new Error('MalwareBazaar HTTP ' + res.status);
  return res.json();
}

// URLhaus — API keysiz
async function urlhausFetch(url) {
  const res = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'url=' + encodeURIComponent(url)
  });
  if (!res.ok) throw new Error('URLhaus HTTP ' + res.status);
  return res.json();
}

// ThreatFox — API keysiz
async function threatfoxFetch(query) {
  const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: 'search_term', search_term: query })
  });
  if (!res.ok) throw new Error('ThreatFox HTTP ' + res.status);
  return res.json();
}

// ── VT polling ──────────────────────────────────────────────

async function poll(id) {
  for (let i = 0; i < 24; i++) {
    await sleep(3000);
    const d = await vtFetch('/analyses/' + id);
    if (d.data.attributes.status === 'completed') return d;
  }
  throw new Error('Vaqt tugadi (72s)');
}

// ── Asosiy scan dispatcher ──────────────────────────────────

async function scan(type) {
  try {
    if (type === 'url') {
      const url = document.getElementById('urlInput').value.trim();
      if (!url) { toast('URL kiriting'); return; }
      showScan('URL TAHLIL QILINMOQDA', 'VirusTotal + URLhaus orqali tekshirilmoqda', '🌐');

      const form = new URLSearchParams();
      form.append('url', url);
      const sub = await vtFetch('/urls', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form.toString()
      });

      document.getElementById('scanSub').textContent = '70+ engine ishlamoqda...';
      const res = await poll(sub.data.id);
      const uid = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const det = await vtFetch('/urls/' + uid).catch(() => null);

      // URLhaus parallel (API keysiz)
      let urlhausData = null;
      try { urlhausData = await urlhausFetch(url); } catch (e) {}

      // URLScan parallel
      let urlscanData = null;
      try {
        const us = await urlscanFetch('/scan/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, visibility: 'public' })
        });
        await sleep(12000);
        urlscanData = await urlscanFetch('/result/' + us.uuid + '/').catch(() => null);
      } catch (e) {}

      stopTimer();
      render(res.data.attributes, det?.data?.attributes,
        { type: 'url', value: url },
        { urlscan: urlscanData, urlhaus: urlhausData }
      );

    } else if (type === 'hash') {
      const h = document.getElementById('hashInput').value.trim();
      if (!h) { toast('Hash kiriting'); return; }
      showScan('HASH QIDIRILMOQDA', 'VirusTotal + MalwareBazaar orqali izlanmoqda', '🔐');

      const [vtRes, mbRes] = await Promise.allSettled([
        vtFetch('/files/' + h),
        mbFetch(h)
      ]);

      stopTimer();

      const vtData = vtRes.status === 'fulfilled' ? vtRes.value?.data?.attributes : null;
      const mbData = mbRes.status === 'fulfilled' ? mbRes.value : null;

      if (!vtData) throw new Error('Hash topilmadi');

      // Hash uchun stats normalize
      if (!vtData.stats && vtData.last_analysis_stats) vtData.stats = vtData.last_analysis_stats;
      if (!vtData.results && vtData.last_analysis_results) vtData.results = vtData.last_analysis_results;

      render(vtData, vtData, { type: 'hash', value: h }, { malwarebazaar: mbData });

    } else if (type === 'file') {
      if (!window._file) { toast('Fayl tanlang'); return; }
      if (window._file.size > 32 * 1024 * 1024) { toast('Maks 32MB'); return; }
      showScan('FAYL SKANERLANMOQDA', window._file.name, '💾');

      const fd = new FormData();
      fd.append('file', window._file);
      const sub = await vtFetch('/files', { method: 'POST', body: fd });
      document.getElementById('scanSub').textContent = '70+ engine tekshirmoqda...';
      const res = await poll(sub.data.id);

      stopTimer();
      render(res.data.attributes, null, { type: 'file', value: window._file.name }, {});

    } else if (type === 'ip') {
      const ip = document.getElementById('ipInput').value.trim();
      if (!ip) { toast('IP kiriting'); return; }
      showScan('IP TAHLIL QILINMOQDA', 'AbuseIPDB + VirusTotal + ThreatFox', '🔎');

      const [vtRes, abuseRes, tfRes] = await Promise.allSettled([
        vtFetch('/ip_addresses/' + ip),
        abuseFetch('/check?ipAddress=' + encodeURIComponent(ip) + '&maxAgeInDays=90&verbose'),
        threatfoxFetch(ip)
      ]);

      stopTimer();
      renderIP(
        ip,
        vtRes.status === 'fulfilled' ? vtRes.value?.data?.attributes : null,
        abuseRes.status === 'fulfilled' ? abuseRes.value?.data : null,
        tfRes.status === 'fulfilled' ? tfRes.value : null
      );

    } else if (type === 'text') {
      const text = document.getElementById('textInput').value.trim();
      if (!text) { toast('Matn kiriting'); return; }
      showScan('MATN TAHLIL QILINMOQDA', 'URL, IP, koordinata, telefon qidirilmoqda...', '📋');
      await scanText(text);
    }

  } catch (e) {
    stopTimer();
    hideAll();
    toast('Xato: ' + e.message, 4000);
    console.error(e);
  }
}
