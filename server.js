const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.resolve(__dirname);

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
};

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'self';",
};

const server = http.createServer((req, res) => {
  // Only allow safe read methods
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Allow': 'GET, HEAD',
      ...SECURITY_HEADERS,
    });
    res.end('405 Method Not Allowed');
    return;
  }

  // Safe URI decoding to prevent DoS via URIError
  let safePath;
  try {
    safePath = decodeURIComponent(req.url.split('?')[0]);
  } catch (err) {
    res.writeHead(400, {
      'Content-Type': 'text/plain; charset=utf-8',
      ...SECURITY_HEADERS,
    });
    res.end('400 Bad Request');
    return;
  }

  if (safePath === '/' || safePath === '') {
    safePath = '/index.html';
  }

  // Strictly resolve and prevent path traversal
  const normalizedPath = path.normalize(safePath).replace(/^(\.\.[\/\\])+/, '');
  const resolvedPath = path.resolve(PUBLIC_DIR, '.' + path.sep + normalizedPath);

  const relative = path.relative(PUBLIC_DIR, resolvedPath);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    res.writeHead(403, {
      'Content-Type': 'text/plain; charset=utf-8',
      ...SECURITY_HEADERS,
    });
    res.end('403 Forbidden');
    return;
  }

  // Block access to hidden files and sensitive dotfiles (.git, .env, etc.)
  const baseName = path.basename(resolvedPath);
  if (baseName.startsWith('.')) {
    res.writeHead(403, {
      'Content-Type': 'text/plain; charset=utf-8',
      ...SECURITY_HEADERS,
    });
    res.end('403 Forbidden');
    return;
  }

  fs.stat(resolvedPath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, {
        'Content-Type': 'text/plain; charset=utf-8',
        ...SECURITY_HEADERS,
      });
      res.end('404 Not Found');
      return;
    }

    const ext = path.extname(resolvedPath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    const cacheControl = ext === '.html' ? 'no-cache' : 'public, max-age=86400';

    const headers = {
      'Content-Type': contentType,
      'Content-Length': stats.size,
      'Cache-Control': cacheControl,
      ...SECURITY_HEADERS,
    };

    if (req.method === 'HEAD') {
      res.writeHead(200, headers);
      res.end();
      return;
    }

    res.writeHead(200, headers);
    const stream = fs.createReadStream(resolvedPath);
    stream.on('error', () => {
      if (!res.headersSent) {
        res.writeHead(500, {
          'Content-Type': 'text/plain; charset=utf-8',
          ...SECURITY_HEADERS,
        });
      }
      res.end();
    });
    stream.pipe(res);
  });
});

server.listen(PORT, () => {
  console.log(`Portfolio preview server running at http://localhost:${PORT}/`);
});
