const express = require('express');
const https = require('https');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'x-apikey, Content-Type',
};

app.options('*', (req, res) => {
  res.set(CORS_HEADERS).sendStatus(204);
});

app.all('/api/vt/*', (req, res) => {
  const vtPath = req.path.replace('/api/vt', '');
  const apiKey = req.headers['x-apikey'];

  if (!apiKey) {
    return res.status(400).json({ error: { message: 'x-apikey header yoq' } });
  }

  const options = {
    hostname: 'www.virustotal.com',
    path: '/api/v3' + vtPath,
    method: req.method,
    headers: {
      'x-apikey': apiKey,
      'Content-Type': req.headers['content-type'] || 'application/octet-stream',
      'User-Agent': 'ThreatScan/1.0',
    },
  };

  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    if (body.length) options.headers['Content-Length'] = body.length;

    const proxyReq = https.request(options, proxyRes => {
      res.set(CORS_HEADERS);
      res.status(proxyRes.statusCode);
      proxyRes.pipe(res);
    });

    proxyReq.on('error', err => {
      res.status(502).json({ error: { message: err.message } });
    });

    if (body.length) proxyReq.write(body);
    proxyReq.end();
  });
});

app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => console.log(`ThreatScan running on port ${PORT}`));