
const headers = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer'
};

const encoder = new TextEncoder();
const SESSION_MS = 8 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 24576;
const MAX_FAILURES = 5;
const WINDOW_MS = 15 * 60 * 1000;
const loginAttempts = new Map();

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...headers, ...extra }
  });

const bad = (message, status = 400, extra = {}) =>
  json({ error: message }, status, extra);

function cookies(request) {
  const result = {};
  for (const part of (request.headers.get('Cookie') || '').split(';')) {
    const pos = part.indexOf('=');
    if (pos >= 0) {
      const name = part.slice(0, pos).trim();
      if (name) result[name] = part.slice(pos + 1).trim();
    }
  }
  return result;
}

function hex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function unhex(value) {
  if (!/^(?:[0-9a-f]{2})+$/i.test(value || '')) return null;
  return Uint8Array.from(value.match(/../g), x => parseInt(x, 16));
}

function equalBytes(a, b) {
  if (!a || !b) return false;
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    diff |= (a[i] || 0) ^ (b[i] || 0);
  }
  return diff === 0;
}

async function sha(value) {
  return new Uint8Array(
    await crypto.subtle.digest('SHA-256', encoder.encode(value))
  );
}

async function hmac(secret, value) {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return new Uint8Array(
    await crypto.subtle.sign('HMAC', key, encoder.encode(value))
  );
}

async function authenticated(request, env) {
  if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32) return false;

  const match = /^(\d{13})\.([0-9a-f]{64})$/i.exec(
    cookies(request).ss_admin || ''
  );
  if (!match) return false;

  const expires = Number(match[1]);
  const now = Date.now();

  if (
    !Number.isSafeInteger(expires) ||
    expires <= now ||
    expires > now + SESSION_MS
  ) return false;

  return equalBytes(
    await hmac(env.SESSION_SECRET, match[1]),
    unhex(match[2])
  );
}

function validOrigin(request, url) {
  return request.headers.get('Origin') === url.origin;
}

function validJsonRequest(request, url) {
  return validOrigin(request, url) &&
    /^application\/json(?:\s*;|$)/i.test(
      request.headers.get('Content-Type') || ''
    );
}

async function readJson(request) {
  const length = Number(request.headers.get('Content-Length') || 0);
  if (length > MAX_BODY_BYTES) throw new Error('Request too large');

  const text = await request.text();
  if (encoder.encode(text).length > MAX_BODY_BYTES) {
    throw new Error('Request too large');
  }
  return JSON.parse(text);
}

function cleanProduct(p) {
  if (!p || typeof p !== 'object' || Array.isArray(p)) {
    throw new Error('Missing product');
  }

  const category = String(p.category || '');
  if (!['web', 'app', 'tech'].includes(category)) {
    throw new Error('Choose a valid category');
  }

  const name = String(p.name || '').trim().slice(0, 120);
  if (!name) throw new Error('Product name required');

  const price = Number(p.price);
  if (!Number.isFinite(price) || price < 0 || price > 10000000) {
    throw new Error('Invalid price');
  }

  const cleanList = value =>
    Array.isArray(value)
      ? value.map(x => String(x).slice(0, 250)).slice(0, 30)
      : [];

  const image = String(p.image || '').trim().slice(0, 500);
  if (image && !/^https:\/\//i.test(image)) {
    throw new Error('Image URL must start with https://');
  }

  return {
    category,
    name,
    price,
    type: String(p.type || 'General').slice(0, 80),
    description: String(p.description || '').slice(0, 1200),
    stack: String(p.stack || '').slice(0, 120),
    icon: String(p.icon || 'Package').slice(0, 12),
    image,
    features: cleanList(p.features),
    components: cleanList(p.components),
    published: p.published ? 1 : 0
  };
}

function mapRow(p) {
  return {
    ...p,
    features: JSON.parse(p.features || '[]'),
    components: JSON.parse(p.components || '[]'),
    published: !!p.published
  };
}

function rateState(request) {
  const ip = (request.headers.get('CF-Connecting-IP') || 'unknown')
    .slice(0, 80);
  const now = Date.now();

  if (loginAttempts.size > 2000) loginAttempts.clear();

  let state = loginAttempts.get(ip);
  if (!state || state.resetAt <= now) {
    state = { failures: 0, resetAt: now + WINDOW_MS };
    loginAttempts.set(ip, state);
  }
  return { ip, state };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (!path.startsWith('/api/')) {
        return env.ASSETS.fetch(request);
      }

      if (!env.DB) {
        return bad('D1 database binding DB is not configured', 503);
      }

      if (path === '/api/products' && request.method === 'GET') {
        const rows = await env.DB.prepare(
          'SELECT * FROM products WHERE published=1 ORDER BY id DESC LIMIT 250'
        ).all();

        return json({ products: rows.results.map(mapRow) });
      }

      if (path === '/api/admin/login' && request.method === 'POST') {
        if (!validJsonRequest(request, url)) {
          return bad('Invalid request origin or content type', 403);
        }

        if (
          !env.ADMIN_PASSWORD ||
          !env.SESSION_SECRET ||
          env.SESSION_SECRET.length < 32
        ) {
          return bad('Admin secrets not configured', 503);
        }

        const { ip, state } = rateState(request);

        if (state.failures >= MAX_FAILURES) {
          return bad('Too many login attempts; try again later', 429, {
            'Retry-After': String(
              Math.ceil((state.resetAt - Date.now()) / 1000)
            )
          });
        }

        const body = await readJson(request);
        const supplied =
          typeof body?.password === 'string' ? body.password : '';

        if (supplied.length > 1024) return bad('Password too long');

        const given = await sha(supplied);
        const actual = await sha(env.ADMIN_PASSWORD);

        if (!equalBytes(given, actual)) {
          state.failures++;
          return bad('Invalid password', 401);
        }

        loginAttempts.delete(ip);

        const expires = String(Date.now() + SESSION_MS);
        const value =
          expires + '.' + hex(await hmac(env.SESSION_SECRET, expires));

        return json({ ok: true }, 200, {
          'Set-Cookie':
            `ss_admin=${value}; Path=/api/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`
        });
      }

      if (path === '/api/admin/logout' && request.method === 'POST') {
        if (!validOrigin(request, url)) {
          return bad('Invalid request origin', 403);
        }
        return json({ ok: true }, 200, {
          'Set-Cookie':
            'ss_admin=; Path=/api/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'
        });
      }

      if (path === '/api/admin/session' && request.method === 'GET') {
        return json({
          authenticated: await authenticated(request, env)
        });
      }

      if (!path.startsWith('/api/admin/')) {
        return bad('Not found', 404);
      }

      if (!(await authenticated(request, env))) {
        return bad('Admin login required', 401);
      }

      if (
        request.method !== 'GET' &&
        !validJsonRequest(request, url)
      ) {
        return bad('Invalid request origin or content type', 403);
      }

      if (path === '/api/admin/products' && request.method === 'GET') {
        const rows = await env.DB.prepare(
          'SELECT * FROM products ORDER BY id DESC LIMIT 500'
        ).all();

        return json({ products: rows.results.map(mapRow) });
      }

      if (path === '/api/admin/products' && request.method === 'POST') {
        const p = cleanProduct(await readJson(request));

        const result = await env.DB.prepare(
          'INSERT INTO products(category,name,type,description,price,icon,image,stack,features,components,published) VALUES(?,?,?,?,?,?,?,?,?,?,?)'
        ).bind(
          p.category, p.name, p.type, p.description, p.price,
          p.icon, p.image, p.stack,
          JSON.stringify(p.features),
          JSON.stringify(p.components),
          p.published
        ).run();

        return json({ ok: true, id: result.meta.last_row_id }, 201);
      }

      const match = /^\/api\/admin\/products\/(\d+)$/.exec(path);

      if (match) {
        const id = Number(match[1]);

        if (!Number.isSafeInteger(id) || id < 1) {
          return bad('Invalid product ID');
        }

        if (request.method === 'PUT') {
          const p = cleanProduct(await readJson(request));

          const result = await env.DB.prepare(
            'UPDATE products SET category=?,name=?,type=?,description=?,price=?,icon=?,image=?,stack=?,features=?,components=?,published=? WHERE id=?'
          ).bind(
            p.category, p.name, p.type, p.description, p.price,
            p.icon, p.image, p.stack,
            JSON.stringify(p.features),
            JSON.stringify(p.components),
            p.published, id
          ).run();

          if (!result.meta.changes) {
            return bad('Product not found', 404);
          }

          return json({ ok: true });
        }

        if (request.method === 'DELETE') {
          const result = await env.DB.prepare(
            'DELETE FROM products WHERE id=?'
          ).bind(id).run();

          if (!result.meta.changes) {
            return bad('Product not found', 404);
          }

          return json({ ok: true });
        }
      }

      return bad('Not found', 404);

    } catch (error) {
      if (error instanceof SyntaxError) {
        return bad('Invalid JSON');
      }

      if (error?.message === 'Request too large') {
        return bad('Request too large', 413);
      }

      if (/^(Missing product|Choose|Product name|Invalid price|Image URL)/.test(
        error?.message || ''
      )) {
        return bad(error.message);
      }

      console.error(error);
      return bad('Server error; check Worker logs and D1 setup', 500);
    }
  }
};
