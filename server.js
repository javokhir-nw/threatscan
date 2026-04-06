const express = require('express');
const https = require('https');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const VT_KEY      = process.env.THREATSCAN_API;
const ABUSE_KEY   = process.env.ABUSE_API;
const URLSCAN_KEY = process.env.URLSCAN_API;
const GEMINI_KEY  = process.env.GEMINI_API;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

app.options('*', (req, res) => res.set(CORS).sendStatus(204));

function proxyReq(options, body, res) {
  if (body.length) options.headers['Content-Length'] = body.length;
  const pr = https.request(options, proxyRes => {
    res.set(CORS).status(proxyRes.statusCode);
    proxyRes.pipe(res);
  });
  pr.on('error', err => res.status(502).json({ error: { message: err.message } }));
  if (body.length) pr.write(body);
  pr.end();
}

function readBody(req) {
  return new Promise(resolve => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
  });
}

// VirusTotal proxy
app.all('/api/vt/*', async (req, res) => {
  if (!VT_KEY) return res.status(503).json({ error: { message: 'THREATSCAN_API key sozlanmagan' } });
  const body = await readBody(req);
  proxyReq({
    hostname: 'www.virustotal.com',
    path: '/api/v3' + req.path.replace('/api/vt', ''),
    method: req.method,
    headers: {
      'x-apikey': VT_KEY,
      'Content-Type': req.headers['content-type'] || 'application/octet-stream',
      'User-Agent': 'ThreatScan/2.0',
    },
  }, body, res);
});

// AbuseIPDB proxy
app.all('/api/abuse/*', async (req, res) => {
  if (!ABUSE_KEY) return res.status(503).json({ error: { message: 'ABUSE_API key sozlanmagan' } });
  const body = await readBody(req);
  const queryPath = req.path.replace('/api/abuse', '') + (req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '');
  proxyReq({
    hostname: 'api.abuseipdb.com',
    path: '/api/v2' + queryPath,
    method: req.method,
    headers: {
      'Key': ABUSE_KEY,
      'Accept': 'application/json',
      'Content-Type': req.headers['content-type'] || 'application/json',
    },
  }, body, res);
});

// URLScan proxy
app.all('/api/urlscan/*', async (req, res) => {
  if (!URLSCAN_KEY) return res.status(503).json({ error: { message: 'URLSCAN_API key sozlanmagan' } });
  const body = await readBody(req);
  proxyReq({
    hostname: 'urlscan.io',
    path: '/api/v1' + req.path.replace('/api/urlscan', ''),
    method: req.method,
    headers: {
      'API-Key': URLSCAN_KEY,
      'Content-Type': req.headers['content-type'] || 'application/json',
    },
  }, body, res);
});

// Gemini AI proxy
app.post('/api/gemini/analyze', async (req, res) => {
  if (!GEMINI_KEY) return res.status(503).json({ error: 'GEMINI_API key sozlanmagan' });

  const body = await readBody(req);
  let parsed;
  try { parsed = JSON.parse(body.toString()); } catch (e) {
    return res.status(400).json({ error: 'JSON xatosi' });
  }

  const text = parsed.text || '';
  const indicators = parsed.indicators || {};

  const prompt = `Sen kiberxavfsizlik mutaxassisisan. Quyidagi matnni tahlil qil va JSON formatda javob ber.

MATN:
"""
${text.slice(0, 2000)}
"""

TOPILGAN INDIKATORLAR:
- URLlar: ${(indicators.urls || []).join(', ') || 'yo\'q'}
- IPlar: ${(indicators.ips || []).join(', ') || 'yo\'q'}
- Telefonlar: ${(indicators.phones || []).join(', ') || 'yo\'q'}
- Usernames: ${(indicators.usernames || []).join(', ') || 'yo\'q'}
- Koordinatalar: ${(indicators.coords || []).join(', ') || 'yo\'q'}

Faqat JSON qaytар, boshqa hech narsa yozma:
{
  "xavf_darajasi": "XAVFSIZ" yoki "SHUBHALI" yoki "XAVFLI",
  "xavf_foiz": 0-100 son,
  "matn_turi": "masalan: reklama, fishing, spam, scam, normal xabar, yangilik...",
  "til": "matn qaysi tilda",
  "xulosa": "2-3 jumlada qisqacha tahlil",
  "sabab": ["xavfli/shubhali bo'lsa sabablari ro'yxat"],
  "tavsiya": "foydalanuvchiga amaliy maslahat"
}`;

  const geminiBody = JSON.stringify({
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: { temperature: 0.1, maxOutputTokens: 1024 }
  });

  const geminiBodyBuf = Buffer.from(geminiBody);

  proxyReq({
    hostname: 'generativelanguage.googleapis.com',
    path: `/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_KEY}`,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
  }, geminiBodyBuf, res);
});

app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`ThreatScan v3 on port ${PORT}`);
  console.log(`VT: ${VT_KEY?'OK':'MISSING'} | Abuse: ${ABUSE_KEY?'OK':'MISSING'} | URLScan: ${URLSCAN_KEY?'OK':'MISSING'} | Gemini: ${GEMINI_KEY?'OK':'MISSING'}`);
});