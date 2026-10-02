import { getStore } from '@netlify/blobs';

const STORE_NAME = 'radilux-license-registry-v1';
const MAX_FAILED = 3;
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const store = getStore(STORE_NAME);

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'Pragma': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
  },
});

function normalizeLicense(value) {
  return String(value ?? '').trim().toUpperCase();
}

function normalizePhone(value) {
  let d = String(value ?? '').replace(/[^0-9]/g, '');
  // Radilux is currently intended for Indian numbers: accept both 10-digit and +91 formats.
  if (d.length === 10) d = `91${d}`;
  return d;
}

function configuredLicenses() {
  return String(process.env.RADILUX_LICENSE_KEYS ?? '')
    .split(/[\n,;]+/)
    .map(normalizeLicense)
    .filter(Boolean);
}

async function hmacHex(value) {
  const secret = String(process.env.RADILUX_AUTH_SECRET ?? '');
  if (!secret) throw new Error('RADILUX_AUTH_SECRET is not configured');
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function b64u(bytes) {
  const s = typeof bytes === 'string' ? bytes : String.fromCharCode(...bytes);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function unb64u(s) {
  const v = String(s).replace(/-/g, '+').replace(/_/g, '/');
  return atob(v + '='.repeat((4 - (v.length % 4)) % 4));
}
async function createToken(payload) {
  const body = b64u(JSON.stringify(payload));
  const sig = await hmacHex(`session.${body}`);
  return `${body}.${sig}`;
}
async function readToken(token) {
  const parts = String(token ?? '').split('.');
  if (parts.length !== 2) throw new Error('bad-token');
  const body = parts[0], given = parts[1];
  const expected = await hmacHex(`session.${body}`);
  if (given.length !== expected.length) throw new Error('bad-token');
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ given.charCodeAt(i);
  if (diff !== 0) throw new Error('bad-token');
  const data = JSON.parse(unb64u(body));
  if (!data.exp || Date.now() > data.exp) throw new Error('expired');
  return data;
}

function licenseBlobKey(licenseHash) {
  return `license/${licenseHash}`;
}

async function getLicenseRecord(blobKey) {
  return store.getWithMetadata(blobKey, { consistency: 'strong', type: 'json' });
}

async function writeExisting(blobKey, record, etag) {
  return store.setJSON(blobKey, record, { onlyIfMatch: etag });
}

async function successResponse(license, phoneHash, phoneLast4) {
  const token = await createToken({
    v: 1,
    lic: await hmacHex(`license:${license}`),
    ph: phoneHash,
    iat: Date.now(),
    exp: Date.now() + SESSION_TTL_MS,
  });
  return {
    ok: true,
    token,
    licenseKey: license,
    phoneLast4,
    expiresAt: Date.now() + SESSION_TTL_MS,
  };
}

async function activate(licenseRaw, phoneRaw) {
  const license = normalizeLicense(licenseRaw);
  const phone = normalizePhone(phoneRaw);
  const configured = configuredLicenses();

  if (!configured.includes(license)) {
    return json({ ok: false, code: 'INVALID_LICENSE', message: 'Invalid license key.' }, 401);
  }
  if (!/^91[0-9]{10}$/.test(phone)) {
    return json({ ok: false, code: 'INVALID_PHONE', message: 'Enter a valid 10-digit Indian phone number.' }, 400);
  }

  const licenseHash = await hmacHex(`license:${license}`);
  const phoneHash = await hmacHex(`phone:${phone}`);
  const blobKey = licenseBlobKey(licenseHash);
  const phoneLast4 = phone.slice(-4);

  // Conditional writes prevent two first-time activations from binding the same license concurrently.
  for (let attempt = 0; attempt < 5; attempt++) {
    const current = await getLicenseRecord(blobKey);
    if (!current) {
      const record = {
        version: 1,
        licenseHash,
        phoneHash,
        phoneLast4,
        status: 'active',
        failedAttempts: 0,
        activatedAt: new Date().toISOString(),
        lastSuccessAt: new Date().toISOString(),
        lastFailureAt: null,
        lockedAt: null,
      };
      const created = await store.setJSON(blobKey, record, { onlyIfNew: true });
      if (created.modified) return json(await successResponse(license, phoneHash, phoneLast4));
      continue;
    }

    const record = current.data ?? {};
    if (record.status === 'locked') {
      return json({
        ok: false,
        code: 'LICENSE_LOCKED',
        message: 'This license is locked after 3 unsuccessful activation attempts.',
      }, 423);
    }

    if (!record.phoneHash) {
      const updated = {
        ...record,
        phoneHash,
        phoneLast4,
        status: 'active',
        failedAttempts: 0,
        activatedAt: record.activatedAt || new Date().toISOString(),
        lastSuccessAt: new Date().toISOString(),
        lastFailureAt: null,
      };
      const wr = await writeExisting(blobKey, updated, current.etag);
      if (wr.modified) return json(await successResponse(license, phoneHash, phoneLast4));
      continue;
    }

    if (record.phoneHash === phoneHash) {
      const updated = {
        ...record,
        status: 'active',
        failedAttempts: 0,
        lastSuccessAt: new Date().toISOString(),
      };
      const wr = await writeExisting(blobKey, updated, current.etag);
      if (wr.modified) return json(await successResponse(license, phoneHash, phoneLast4));
      continue;
    }

    const failedAttempts = Number(record.failedAttempts || 0) + 1;
    const locked = failedAttempts >= MAX_FAILED;
    const updated = {
      ...record,
      failedAttempts,
      status: locked ? 'locked' : 'active',
      lastFailureAt: new Date().toISOString(),
      ...(locked ? { lockedAt: new Date().toISOString() } : {}),
    };
    const wr = await writeExisting(blobKey, updated, current.etag);
    if (wr.modified) {
      if (locked) {
        return json({
          ok: false,
          code: 'LICENSE_LOCKED',
          message: 'ILLEGAL / UNAUTHORIZED USE WARNING: this license has been locked after 3 unsuccessful attempts.',
          attemptsRemaining: 0,
        }, 423);
      }
      return json({
        ok: false,
        code: 'PHONE_MISMATCH',
        message: 'This license is already bound to another phone number.',
        attemptsRemaining: Math.max(0, MAX_FAILED - failedAttempts),
      }, 409);
    }
  }

  return json({ ok: false, code: 'CONCURRENT_UPDATE', message: 'The license changed while it was being checked. Please try again.' }, 409);
}

async function verify(token) {
  let payload;
  try {
    payload = await readToken(token);
  } catch (e) {
    return json({ ok: false, code: e?.message === 'expired' ? 'SESSION_EXPIRED' : 'SESSION_INVALID', message: 'Your license session is no longer valid. Please activate again.' }, 401);
  }

  const current = await getLicenseRecord(licenseBlobKey(payload.lic));
  if (!current || !current.data) {
    return json({ ok: false, code: 'SESSION_INVALID', message: 'License record not found.' }, 401);
  }
  const record = current.data;
  if (record.status === 'locked') {
    return json({ ok: false, code: 'LICENSE_LOCKED', message: 'ILLEGAL / UNAUTHORIZED USE WARNING: this license is locked.' }, 423);
  }
  if (!record.phoneHash || record.phoneHash !== payload.ph) {
    return json({ ok: false, code: 'SESSION_INVALID', message: 'License binding could not be verified.' }, 401);
  }

  const configured = configuredLicenses();
  // Payload contains only a hash of the license, so re-derive it from configured values.
  let license = '';
  for (const candidate of configured) {
    const h = await hmacHex(`license:${candidate}`);
    if (h === payload.lic) { license = candidate; break; }
  }
  if (!license) return json({ ok: false, code: 'INVALID_LICENSE', message: 'License is no longer active.' }, 401);

  return json({ ok: true, licenseKey: license, phoneLast4: record.phoneLast4 || '' });
}

async function adminReset(licenseRaw, request) {
  const adminSecret = String(process.env.RADILUX_ADMIN_SECRET ?? '');
  const supplied = String(request.headers.get('x-radilux-admin-secret') ?? '');
  if (!adminSecret || supplied !== adminSecret) {
    return json({ ok: false, code: 'ADMIN_UNAUTHORIZED', message: 'Administrator authorization failed.' }, 403);
  }
  const license = normalizeLicense(licenseRaw);
  if (!configuredLicenses().includes(license)) return json({ ok: false, code: 'INVALID_LICENSE', message: 'Unknown license key.' }, 404);
  const licenseHash = await hmacHex(`license:${license}`);
  await store.delete(licenseBlobKey(licenseHash));
  return json({ ok: true, message: 'License binding and lock have been reset. The next successful activation will bind a new phone number.' });
}

export default async (request) => {
  if (request.method !== 'POST') return json({ ok: false, code: 'METHOD_NOT_ALLOWED', message: 'Use POST.' }, 405);
  try {
    const body = await request.json();
    const action = String(body?.action || '');
    if (!process.env.RADILUX_LICENSE_KEYS || !process.env.RADILUX_AUTH_SECRET) {
      return json({ ok: false, code: 'SERVER_CONFIG', message: 'Radilux license service is not configured on Netlify.' }, 500);
    }
    if (action === 'activate') return await activate(body.licenseKey, body.phone);
    if (action === 'verify') return await verify(body.token);
    if (action === 'adminReset') return await adminReset(body.licenseKey, request);
    return json({ ok: false, code: 'BAD_ACTION', message: 'Unsupported license action.' }, 400);
  } catch (e) {
    console.error('Radilux license function error:', e);
    return json({ ok: false, code: 'SERVER_ERROR', message: 'The license server encountered an error. Please try again.' }, 500);
  }
};
