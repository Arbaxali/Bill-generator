import crypto from 'node:crypto';

const COOKIE_NAME = 'fgsb_session';
const SESSION_TTL_SECONDS = 12 * 60 * 60;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function normalizeHost(value) {
  const input = String(value || '').trim();
  if (!input) return '';
  try {
    const url = new URL(input.includes('://') ? input : `https://${input}`);
    if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) return '';
    return url.host.toLowerCase();
  } catch {
    return '';
  }
}

function equalSecret(actual, expected) {
  const a = Buffer.from(String(actual));
  const b = Buffer.from(String(expected));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function readCookie(request, name) {
  const prefix = `${name}=`;
  for (const part of String(request.headers.cookie || '').split(';')) {
    const value = part.trim();
    if (value.startsWith(prefix)) return value.slice(prefix.length);
  }
  return '';
}

function renderLoginPage(message = '') {
  const notice = message ? '<p role="alert">Sign-in failed. Check the password and try again.</p>' : '';
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign in - Free GST Billing</title></head>
<body><main><h1>Free GST Billing</h1><p>Enter the deployment password to continue.</p>${notice}
<form method="post" action="/auth/login">
<label for="password">Password</label>
<input id="password" name="password" type="password" required autocomplete="current-password" autofocus>
<button type="submit">Sign in</button>
</form></main></body></html>`;
}

export function createDeploymentAuth(env = process.env) {
  const enabled = env.FGSB_PUBLIC_DEPLOYMENT === '1';
  if (!enabled) {
    return {
      enabled: false,
      middleware: (_req, _res, next) => next(),
      loginPage: (_req, res) => res.status(404).end(),
      login: (_req, res) => res.status(404).end(),
      logout: (_req, res) => res.status(404).end(),
    };
  }

  const password = String(env.FGSB_AUTH_PASSWORD || '');
  const sessionSecret = String(env.FGSB_SESSION_SECRET || '');
  const allowedHosts = new Set([
    env.RENDER_EXTERNAL_HOSTNAME,
    ...String(env.FGSB_ALLOWED_HOSTS || '').split(','),
  ].map(normalizeHost).filter(Boolean));
  if (password.length < 24) throw new Error('FGSB_AUTH_PASSWORD must be at least 24 characters for public deployment.');
  if (sessionSecret.length < 32) throw new Error('FGSB_SESSION_SECRET must be at least 32 characters for public deployment.');
  if (allowedHosts.size === 0) throw new Error('Set RENDER_EXTERNAL_HOSTNAME or FGSB_ALLOWED_HOSTS for public deployment.');

  const signingKey = crypto.createHmac('sha256', sessionSecret).update(password).digest();

  function createSession() {
    const payload = `${Date.now()}.${crypto.randomBytes(24).toString('base64url')}`;
    const signature = crypto.createHmac('sha256', signingKey).update(payload).digest('base64url');
    return `${payload}.${signature}`;
  }

  function hasValidSession(req) {
    const token = readCookie(req, COOKIE_NAME);
    const parts = token.split('.');
    if (parts.length !== 3 || !/^\d+$/.test(parts[0])) return false;
    const createdAt = Number(parts[0]);
    if (!Number.isSafeInteger(createdAt) || Date.now() - createdAt > SESSION_TTL_SECONDS * 1000 || createdAt > Date.now()) return false;
    const payload = `${parts[0]}.${parts[1]}`;
    const expected = crypto.createHmac('sha256', signingKey).update(payload).digest('base64url');
    return equalSecret(parts[2], expected);
  }

  function middleware(req, res, next) {
    if (req.method === 'GET' && req.path === '/api/health') return next();

    const host = normalizeHost(req.headers.host);
    if (!allowedHosts.has(host)) return res.status(403).json({ error: 'Host not allowed' });

    const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
    if (forwardedProto !== 'https') return res.status(426).json({ error: 'HTTPS is required' });
    res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.set('X-Content-Type-Options', 'nosniff');

    if (req.headers['sec-fetch-site'] === 'cross-site') {
      return res.status(403).json({ error: 'Cross-site requests are not allowed' });
    }

    const origin = req.headers.origin;
    const unsafeMethod = !SAFE_METHODS.has(req.method);
    if (!origin && unsafeMethod) return res.status(403).json({ error: 'Same-origin request required' });
    if (origin) {
      let parsedOrigin;
      try {
        parsedOrigin = new URL(origin);
      } catch {
        return res.status(403).json({ error: 'Invalid origin' });
      }
      if (parsedOrigin.protocol !== 'https:' || parsedOrigin.host.toLowerCase() !== host) {
        return res.status(403).json({ error: 'Cross-origin request refused' });
      }
    }

    if (req.method === 'GET' && req.path === '/login') return next();
    if (req.method === 'POST' && req.path === '/auth/login') return next();
    if (!hasValidSession(req)) {
      if (req.method === 'GET' && !req.path.startsWith('/api/')) return res.redirect(302, '/login');
      return res.status(401).json({ error: 'Sign-in required' });
    }
    next();
  }

  function loginPage(req, res) {
    if (hasValidSession(req)) return res.redirect(302, '/');
    res.set({
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      'X-Content-Type-Options': 'nosniff',
    });
    return res.type('html').send(renderLoginPage(req.query.error === '1'));
  }

  function login(req, res) {
    if (!equalSecret(req.body?.password || '', password)) {
      res.set('Cache-Control', 'no-store');
      return res.status(401).type('html').send(renderLoginPage('1'));
    }
    res.set({
      'Cache-Control': 'no-store',
      'Set-Cookie': `${COOKIE_NAME}=${createSession()}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_SECONDS}`,
    });
    return res.redirect(303, '/');
  }

  function logout(_req, res) {
    res.set('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`);
    return res.redirect(303, '/login');
  }

  return { enabled: true, middleware, loginPage, login, logout };
}
