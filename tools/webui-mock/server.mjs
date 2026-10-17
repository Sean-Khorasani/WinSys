// Dev-only mock server for the WinTCP Web UI.
// Node built-ins only. Serves wintcp/webui and fixture JSON.
// Never staged by the build. Never shipped.
//
// Usage:
//   node tools/webui-mock/server.mjs [port]
//
// Serves:
//   /                     -> index.html with token substitution
//   /app.js, /app.css     -> static files
//   /api/*                -> fixture JSON from wintcp/tests/webui-fixtures/

import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { join, extname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const ROOT = join(__dirname, '..', '..');
const WEBUI_DIR = join(ROOT, 'wintcp', 'webui');
const FIXTURES_DIR = join(ROOT, 'wintcp', 'tests', 'webui-fixtures');

const PORT = parseInt(process.argv[2] || '8765', 10);
const TOKEN = 'mock-token-12345';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.map': 'application/json',
};

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    'Content-Type': headers['Content-Type'] || 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Connection': 'close',
    ...headers,
  });
  res.end(body);
}

async function serveStatic(res, filePath) {
  try {
    const st = await stat(filePath);
    if (!st.isFile()) {
      send(res, 404, '{"error":"not found"}');
      return;
    }
    const data = await readFile(filePath);
    const ext = extname(filePath).toLowerCase();
    send(res, 200, data, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
  } catch {
    send(res, 404, '{"error":"not found"}');
  }
}

async function serveFixture(res, name) {
  const filePath = join(FIXTURES_DIR, name + '.json');
  await serveStatic(res, filePath);
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = normalize(url.pathname).replace(/^([/\\])+/, '');

  // API routes
  if (path.startsWith('api/')) {
    const endpoint = path.slice(4);
    if (endpoint === 'health') {
      send(res, 200, JSON.stringify({ status: 'ok', version: 'mock-1' }));
      return;
    }
    if (endpoint === 'connections') {
      await serveFixture(res, 'connections');
      return;
    }
    if (endpoint === 'templates') {
      await serveFixture(res, 'templates');
      return;
    }
    if (endpoint === 'config') {
      await serveFixture(res, 'config');
      return;
    }
    if (endpoint === 'audit') {
      await serveFixture(res, 'audit');
      return;
    }
    if (endpoint === 'metrics/catalog') {
      await serveFixture(res, 'metrics-catalog');
      return;
    }
    if (endpoint === 'metrics/now') {
      await serveFixture(res, 'metrics-now');
      return;
    }
    if (endpoint === 'metrics/history') {
      await serveFixture(res, 'metrics-history');
      return;
    }
    if (endpoint === 'capabilities') {
      await serveFixture(res, 'capabilities');
      return;
    }
    if (endpoint === 'system/info') {
      await serveFixture(res, 'system-info');
      return;
    }
    if (endpoint === 'processes') {
      await serveFixture(res, 'processes');
      return;
    }
    if (endpoint === 'network/summary') {
      await serveFixture(res, 'network-summary');
      return;
    }
    if (endpoint === 'geo/summary') {
      await serveFixture(res, 'geo-summary');
      return;
    }
    send(res, 404, '{"error":"unknown endpoint"}');
    return;
  }

  // Static files
  if (path === '' || path === 'index.html') {
    try {
      let html = await readFile(join(WEBUI_DIR, 'index.html'), 'utf-8');
      html = html.replace('{{WIN_TCP_TOKEN}}', TOKEN);
      send(res, 200, html, { 'Content-Type': 'text/html; charset=utf-8' });
    } catch {
      send(res, 404, '{"error":"index.html not found"}');
    }
    return;
  }

  // Prevent path traversal
  if (path.includes('..')) {
    send(res, 403, '{"error":"forbidden"}');
    return;
  }

  const filePath = join(WEBUI_DIR, path);
  await serveStatic(res, filePath);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`Mock Web UI server running at http://127.0.0.1:${PORT}/`);
  console.log(`Serving: ${WEBUI_DIR}`);
  console.log(`Fixtures: ${FIXTURES_DIR}`);
});
