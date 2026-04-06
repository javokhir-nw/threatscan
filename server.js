const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// VT API proxy — CORS muammosini hal qiladi
app.use('/api/vt', createProxyMiddleware({
  target: 'https://www.virustotal.com/api/v3',
  changeOrigin: true,
  pathRewrite: { '^/api/vt': '' },
  on: {
    proxyReq: (proxyReq, req) => {
      const key = req.headers['x-apikey'];
      if (key) proxyReq.setHeader('x-apikey', key);
    },
    proxyRes: (proxyRes) => {
      proxyRes.headers['Access-Control-Allow-Origin'] = '*';
    }
  }
}));

// CORS preflight
app.options('*', (req, res) => {
  res.set({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'x-apikey,Content-Type'
  }).sendStatus(204);
});

// Static HTML
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => console.log(`ThreatScan running on port ${PORT}`));
