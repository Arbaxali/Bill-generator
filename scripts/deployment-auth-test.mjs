import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 47531 + Math.floor(Math.random() * 1000);
const HOST = `127.0.0.1:${PORT}`;
const PASSWORD = 'deployment-test-password-at-least-24-characters';
const TEMP = fs.mkdtempSync(path.join(os.tmpdir(), 'fgsb-deployment-auth-'));
const BOOKS = path.join(TEMP, 'books');
fs.mkdirSync(BOOKS);

const child = spawn(process.execPath, [path.join(ROOT, 'server.js')], {
  cwd: ROOT,
  env: {
    ...process.env,
    FGSB_PUBLIC_DEPLOYMENT: '1',
    FGSB_HOME: BOOKS,
    FGSB_AUTH_PASSWORD: PASSWORD,
    FGSB_SESSION_SECRET: 'deployment-test-session-secret-long-enough',
    RENDER_EXTERNAL_HOSTNAME: HOST,
    FGSB_ALLOWED_HOSTS: '',
    FGSB_PHONE_ACCESS: '',
    FGSB_PIN: '',
    PORT: String(PORT),
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});

let output = '';
child.stdout.on('data', (data) => { output += data; });
child.stderr.on('data', (data) => { output += data; });

const headers = {
  Host: HOST,
  'X-Forwarded-Proto': 'https',
};
async function request(url, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port: PORT,
      path: url,
      method: options.method || 'GET',
      headers: { ...headers, ...(options.headers || {}) },
    }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: {
          get(name) {
            const value = res.headers[name.toLowerCase()];
            return Array.isArray(value) ? value.join(', ') : value || null;
          },
        },
        text: async () => body,
        json: async () => JSON.parse(body),
      }));
    });
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

async function waitForHealth() {
  for (let attempt = 0; attempt < 150; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Server exited during startup:\n${output}`);
    try {
      const response = await request('/api/health');
      if (response.status >= 200 && response.status < 300) return response;
    } catch {
      await delay(200);
      continue;
    }
    await delay(200);
  }
  throw new Error(`Server did not become healthy:\n${output}`);
}

try {
  const health = await waitForHealth();
  assert.deepEqual(await health.json(), { ok: true }, 'public health endpoint should disclose only a status');

  const unauthenticated = await request('/api/version');
  assert.equal(unauthenticated.status, 401, `API should require a session: ${await unauthenticated.text()}`);

  const wrongHost = await request('/api/version', { headers: { Host: 'attacker.example' } });
  assert.equal(wrongHost.status, 403, 'unknown Host should be rejected');

  const badOrigin = await request('/api/version', { headers: { Origin: 'https://attacker.example' } });
  assert.equal(badOrigin.status, 403, 'cross-origin requests should be rejected');

  const badLogin = await request('/auth/login', {
    method: 'POST',
    headers: { Origin: `https://${HOST}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'password=wrong',
  });
  assert.equal(badLogin.status, 401, 'incorrect deployment password should not establish a session');

  const login = await request('/auth/login', {
    method: 'POST',
    headers: { Origin: `https://${HOST}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `password=${encodeURIComponent(PASSWORD)}`,
  });
  assert.equal(login.status, 303, 'correct password should establish a session');
  const cookie = login.headers.get('set-cookie');
  assert.match(cookie || '', /^fgsb_session=.*HttpOnly; Secure; SameSite=Strict; Path=\//);

  const api = await request('/api/version', { headers: { Cookie: cookie.split(';')[0] } });
  assert.equal(api.status, 200, 'a valid session should access the API');

  const noOriginMutation = await request('/api/lock/set', {
    method: 'POST',
    headers: { Cookie: cookie.split(';')[0], 'Content-Type': 'application/json' },
    body: JSON.stringify({ pin: '123456' }),
  });
  assert.equal(noOriginMutation.status, 403, 'state changes should require same-origin requests');

  const logout = await request('/auth/logout', {
    method: 'POST',
    headers: { Cookie: cookie.split(';')[0], Origin: `https://${HOST}` },
  });
  assert.equal(logout.status, 303, 'logout should clear the session');

  console.log('deployment-auth: passed - health privacy, host/origin checks, login, API guard and logout');
} catch (error) {
  console.error(error);
  process.exitCode = 1;
} finally {
  child.kill();
  await Promise.race([
    new Promise((resolve) => child.once('exit', resolve)),
    delay(5000),
  ]);
  fs.rmSync(TEMP, { recursive: true, force: true });
}
