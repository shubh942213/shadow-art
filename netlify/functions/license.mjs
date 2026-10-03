import { getStore } from '@netlify/blobs';

const STORE_NAME = 'radilux-license-registry-v1';
const MAX_FAILED = 3;
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const store = getStore(STORE_NAME);

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, Cache-Control, x-radilux-admin-secret',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'Pragma': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
    ...CORS_HEADERS,
  },
});

function normalizeLicense(value) {
  return String(value ?? '').trim().toUpperCase();
}

function normalizePhone(value) {
  let d = String(value ?? '').replace(/[^0-9]/g, '');
  if (d.length === 10) d = `91${d}`;
  return d;
}

function normalizeUserId(value) {
  const id = String(value ?? '')
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9_-]/g, '')
    .slice(0, 24);
  return id;
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

function randomHex(bytes = 4) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

function makeLicenseKey(userId) {
  return `RDLX-${userId}-${randomHex(4)}-${randomHex(4)}`;
}

function validityToExpiry(validityDays) {
  const days = Number(validityDays);
  if (!Number.isFinite(days) || days < 0 || days > 3650) return undefined;
  if (days === 0) return null;
  const d = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  return d.toISOString();
}

function isExpired(record) {
  return !!record?.expiresAt && Date.now() >= Date.parse(record.expiresAt);
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

async function successResponse(license, phoneHash, phoneLast4, record = {}) {
  const token = await createToken({
    v: 2,
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
    expiresAt: record.expiresAt ?? null,
    sessionExpiresAt: Date.now() + SESSION_TTL_MS,
  };
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

async function isAdmin(request) {
  const expected = String(process.env.RADILUX_ADMIN_SECRET ?? '');
  const supplied = String(request.headers.get('x-radilux-admin-secret') ?? '');
  return !!expected && supplied === expected;
}

async function activate(licenseRaw, phoneRaw) {
  const license = normalizeLicense(licenseRaw);
  const phone = normalizePhone(phoneRaw);

  if (!/^91[0-9]{10}$/.test(phone)) {
    return json({ ok: false, code: 'INVALID_PHONE', message: 'Enter a valid 10-digit Indian phone number.' }, 400);
  }
  if (!license) {
    return json({ ok: false, code: 'INVALID_LICENSE', message: 'Invalid license key.' }, 401);
  }

  const licenseHash = await hmacHex(`license:${license}`);
  const phoneHash = await hmacHex(`phone:${phone}`);
  const blobKey = licenseBlobKey(licenseHash);
  const phoneLast4 = phone.slice(-4);
  let current = await getLicenseRecord(blobKey);

  // Backward compatibility: if an old RADILUX_LICENSE_KEYS variable exists,
  // automatically create a lifetime license record the first time it is used.
  if (!current && configuredLicenses().includes(license)) {
    const legacyRecord = {
      version: 2,
      licenseHash,
      licenseKey: license,
      userId: 'LEGACY',
      status: 'available',
      failedAttempts: 0,
      phoneHash: null,
      phoneLast4: '',
      createdAt: new Date().toISOString(),
      activatedAt: null,
      lastSuccessAt: null,
      lastFailureAt: null,
      lockedAt: null,
      revokedAt: null,
      expiresAt: null,
      validityDays: 0,
      note: 'Imported automatically from RADILUX_LICENSE_KEYS',
      source: 'legacy-env',
    };
    const created = await store.setJSON(blobKey, legacyRecord, { onlyIfNew: true });
    if (created.modified) current = { data: legacyRecord, etag: created.etag };
    else current = await getLicenseRecord(blobKey);
  }

  if (!current || !current.data) {
    return json({ ok: false, code: 'INVALID_LICENSE', message: 'Invalid license key.' }, 401);
  }

  for (let attempt = 0; attempt < 6; attempt++) {
    current = await getLicenseRecord(blobKey);
    if (!current || !current.data) {
      return json({ ok: false, code: 'INVALID_LICENSE', message: 'Invalid license key.' }, 401);
    }
    const record = current.data ?? {};

    if (record.status === 'revoked') {
      return json({ ok: false, code: 'LICENSE_REVOKED', message: 'This license has been revoked by Radilux.' }, 403);
    }
    if (isExpired(record)) {
      if (record.status !== 'expired') {
        await writeExisting(blobKey, { ...record, status: 'expired' }, current.etag);
      }
      return json({ ok: false, code: 'LICENSE_EXPIRED', message: 'This license has expired. Please contact Radilux support.' }, 410);
    }
    if (record.status === 'locked') {
      return json({
        ok: false,
        code: 'LICENSE_LOCKED',
        message: 'ILLEGAL / UNAUTHORIZED USE WARNING: this license has been locked after 3 unsuccessful attempts.',
        attemptsRemaining: 0,
      }, 423);
    }

    if (!record.phoneHash) {
      const updated = {
        ...record,
        version: 2,
        licenseKey: record.licenseKey || license,
        phoneHash,
        phoneLast4,
        status: 'active',
        failedAttempts: 0,
        activatedAt: record.activatedAt || new Date().toISOString(),
        lastSuccessAt: new Date().toISOString(),
        lastFailureAt: null,
        lockedAt: null,
      };
      const wr = await writeExisting(blobKey, updated, current.etag);
      if (wr.modified) return json(await successResponse(license, phoneHash, phoneLast4, updated));
      continue;
    }

    if (record.phoneHash === phoneHash) {
      const updated = {
        ...record,
        licenseKey: record.licenseKey || license,
        status: 'active',
        failedAttempts: 0,
        lastSuccessAt: new Date().toISOString(),
      };
      const wr = await writeExisting(blobKey, updated, current.etag);
      if (wr.modified) return json(await successResponse(license, phoneHash, phoneLast4, updated));
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
  if (record.status === 'revoked') {
    return json({ ok: false, code: 'LICENSE_REVOKED', message: 'This license has been revoked by Radilux.' }, 403);
  }
  if (isExpired(record)) {
    if (record.status !== 'expired') {
      await writeExisting(licenseBlobKey(payload.lic), { ...record, status: 'expired' }, current.etag);
    }
    return json({ ok: false, code: 'LICENSE_EXPIRED', message: 'This license has expired. Please contact Radilux support.' }, 410);
  }
  if (!record.phoneHash || record.phoneHash !== payload.ph) {
    return json({ ok: false, code: 'SESSION_INVALID', message: 'License binding could not be verified.' }, 401);
  }

  return json({
    ok: true,
    licenseKey: record.licenseKey || '',
    phoneLast4: record.phoneLast4 || '',
    expiresAt: record.expiresAt ?? null,
    userId: record.userId || '',
  });
}

async function requireAdmin(request) {
  if (!(await isAdmin(request))) {
    return json({ ok: false, code: 'ADMIN_UNAUTHORIZED', message: 'Administrator authorization failed.' }, 403);
  }
  return null;
}

async function adminGenerate(body, request) {
  const denied = await requireAdmin(request);
  if (denied) return denied;

  const userId = normalizeUserId(body?.userId);
  const quantity = Math.max(1, Math.min(500, Math.floor(Number(body?.quantity ?? 1))));
  const validityDays = Number(body?.validityDays ?? 365);
  const expiry = validityToExpiry(validityDays);
  const note = String(body?.note ?? '').trim().slice(0, 120);
  if (!userId) return json({ ok: false, code: 'BAD_USER_ID', message: 'Enter a customer/user ID.' }, 400);
  if (expiry === undefined) return json({ ok: false, code: 'BAD_VALIDITY', message: 'Validity must be 0 (lifetime) or between 1 and 3650 days.' }, 400);

  const generated = [];
  for (let i = 0; i < quantity; i++) {
    let saved = false;
    for (let retry = 0; retry < 10 && !saved; retry++) {
      const license = makeLicenseKey(userId);
      const licenseHash = await hmacHex(`license:${license}`);
      const blobKey = licenseBlobKey(licenseHash);
      const now = new Date().toISOString();
      const record = {
        version: 2,
        licenseHash,
        licenseKey: license,
        userId,
        status: 'available',
        failedAttempts: 0,
        phoneHash: null,
        phoneLast4: '',
        createdAt: now,
        activatedAt: null,
        lastSuccessAt: null,
        lastFailureAt: null,
        lockedAt: null,
        revokedAt: null,
        expiresAt: expiry,
        validityDays,
        note,
        source: 'admin-generated',
      };
      const wr = await store.setJSON(blobKey, record, { onlyIfNew: true });
      if (wr.modified) {
        generated.push({
          licenseKey: license,
          userId,
          status: 'available',
          createdAt: now,
          expiresAt: expiry,
          validityDays,
          note,
        });
        saved = true;
      }
    }
    if (!saved) return json({ ok: false, code: 'KEY_GENERATION_FAILED', message: 'Could not create a unique license key. Please try again.' }, 500);
  }

  return json({ ok: true, licenses: generated });
}

async function adminRegister(body, request) {
  const denied = await requireAdmin(request);
  if (denied) return denied;

  const license = normalizeLicense(body?.licenseKey);
  const userId = normalizeUserId(body?.userId) || 'IMPORTED';
  const validityDays = Number(body?.validityDays ?? 0);
  const expiry = validityToExpiry(validityDays);
  const note = String(body?.note ?? '').trim().slice(0, 120);
  if (!license || !/^RDLX-[A-Z0-9_-]+-.+-.$/i.test(license)) {
    // Existing legacy keys are allowed; this validation intentionally stays light.
  }
  if (expiry === undefined) return json({ ok: false, code: 'BAD_VALIDITY', message: 'Validity must be 0 (lifetime) or between 1 and 3650 days.' }, 400);
  if (!license) return json({ ok: false, code: 'BAD_LICENSE', message: 'Enter a license key.' }, 400);

  const licenseHash = await hmacHex(`license:${license}`);
  const blobKey = licenseBlobKey(licenseHash);
  const existing = await getLicenseRecord(blobKey);
  if (existing) return json({ ok: false, code: 'LICENSE_EXISTS', message: 'That license key is already registered.' }, 409);

  const now = new Date().toISOString();
  const record = {
    version: 2,
    licenseHash,
    licenseKey: license,
    userId,
    status: 'available',
    failedAttempts: 0,
    phoneHash: null,
    phoneLast4: '',
    createdAt: now,
    activatedAt: null,
    lastSuccessAt: null,
    lastFailureAt: null,
    lockedAt: null,
    revokedAt: null,
    expiresAt: expiry,
    validityDays,
    note,
    source: 'admin-registered',
  };
  const wr = await store.setJSON(blobKey, record, { onlyIfNew: true });
  if (!wr.modified) return json({ ok: false, code: 'LICENSE_EXISTS', message: 'That license key is already registered.' }, 409);
  return json({ ok: true, license: record });
}

async function adminImportConfigured(request) {
  const denied = await requireAdmin(request);
  if (denied) return denied;
  const keys = configuredLicenses();
  const imported = [];
  const skipped = [];
  for (const license of keys) {
    const licenseHash = await hmacHex(`license:${license}`);
    const blobKey = licenseBlobKey(licenseHash);
    const existing = await getLicenseRecord(blobKey);
    if (existing) {
      skipped.push(license);
      continue;
    }
    const now = new Date().toISOString();
    const record = {
      version: 2,
      licenseHash,
      licenseKey: license,
      userId: 'IMPORTED',
      status: 'available',
      failedAttempts: 0,
      phoneHash: null,
      phoneLast4: '',
      createdAt: now,
      activatedAt: null,
      lastSuccessAt: null,
      lastFailureAt: null,
      lockedAt: null,
      revokedAt: null,
      expiresAt: null,
      validityDays: 0,
      note: 'Imported from RADILUX_LICENSE_KEYS',
      source: 'legacy-env-import',
    };
    const wr = await store.setJSON(blobKey, record, { onlyIfNew: true });
    if (wr.modified) imported.push(license);
    else skipped.push(license);
  }
  return json({ ok: true, imported, skipped, totalConfigured: keys.length });
}

async function adminList(request) {
  const denied = await requireAdmin(request);
  if (denied) return denied;
  const { blobs = [] } = await store.list({ prefix: 'license/' });
  const records = [];
  for (const blob of blobs) {
    const current = await getLicenseRecord(blob.key);
    if (!current?.data) continue;
    const r = current.data;
    let status = r.status || 'available';
    if (status === 'active' && isExpired(r)) status = 'expired';
    records.push({
      licenseKey: r.licenseKey || '',
      userId: r.userId || '',
      status,
      failedAttempts: Number(r.failedAttempts || 0),
      phoneLast4: r.phoneLast4 || '',
      createdAt: r.createdAt || '',
      activatedAt: r.activatedAt || null,
      expiresAt: r.expiresAt ?? null,
      validityDays: Number(r.validityDays || 0),
      note: r.note || '',
      source: r.source || '',
    });
  }
  records.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  return json({ ok: true, licenses: records, total: records.length });
}

async function adminReset(body, request) {
  const denied = await requireAdmin(request);
  if (denied) return denied;
  const license = normalizeLicense(body?.licenseKey);
  if (!license) return json({ ok: false, code: 'BAD_LICENSE', message: 'Enter a license key.' }, 400);
  const licenseHash = await hmacHex(`license:${license}`);
  const blobKey = licenseBlobKey(licenseHash);
  const current = await getLicenseRecord(blobKey);
  if (!current?.data) return json({ ok: false, code: 'INVALID_LICENSE', message: 'License record not found.' }, 404);
  const r = current.data;
  const expired = isExpired(r);
  const updated = {
    ...r,
    status: expired ? 'expired' : 'available',
    phoneHash: null,
    phoneLast4: '',
    failedAttempts: 0,
    activatedAt: null,
    lastSuccessAt: null,
    lastFailureAt: null,
    lockedAt: null,
  };
  const wr = await writeExisting(blobKey, updated, current.etag);
  if (!wr.modified) return json({ ok: false, code: 'CONCURRENT_UPDATE', message: 'The license changed. Refresh and try again.' }, 409);
  return json({ ok: true, message: 'License binding and lock have been reset.' });
}

async function adminRevoke(body, request) {
  const denied = await requireAdmin(request);
  if (denied) return denied;
  const license = normalizeLicense(body?.licenseKey);
  if (!license) return json({ ok: false, code: 'BAD_LICENSE', message: 'Enter a license key.' }, 400);
  const licenseHash = await hmacHex(`license:${license}`);
  const blobKey = licenseBlobKey(licenseHash);
  const current = await getLicenseRecord(blobKey);
  if (!current?.data) return json({ ok: false, code: 'INVALID_LICENSE', message: 'License record not found.' }, 404);
  const updated = { ...current.data, status: 'revoked', revokedAt: new Date().toISOString() };
  const wr = await writeExisting(blobKey, updated, current.etag);
  if (!wr.modified) return json({ ok: false, code: 'CONCURRENT_UPDATE', message: 'The license changed. Refresh and try again.' }, 409);
  return json({ ok: true, message: 'License revoked.' });
}

async function adminRestore(body, request) {
  const denied = await requireAdmin(request);
  if (denied) return denied;
  const license = normalizeLicense(body?.licenseKey);
  if (!license) return json({ ok: false, code: 'BAD_LICENSE', message: 'Enter a license key.' }, 400);
  const licenseHash = await hmacHex(`license:${license}`);
  const blobKey = licenseBlobKey(licenseHash);
  const current = await getLicenseRecord(blobKey);
  if (!current?.data) return json({ ok: false, code: 'INVALID_LICENSE', message: 'License record not found.' }, 404);
  if (isExpired(current.data)) return json({ ok: false, code: 'LICENSE_EXPIRED', message: 'The license validity has expired.' }, 410);
  const updated = { ...current.data, status: current.data.phoneHash ? 'active' : 'available', revokedAt: null };
  const wr = await writeExisting(blobKey, updated, current.etag);
  if (!wr.modified) return json({ ok: false, code: 'CONCURRENT_UPDATE', message: 'The license changed. Refresh and try again.' }, 409);
  return json({ ok: true, message: 'License restored.' });
}

async function adminDelete(body, request) {
  const denied = await requireAdmin(request);
  if (denied) return denied;
  const license = normalizeLicense(body?.licenseKey);
  if (!license) return json({ ok: false, code: 'BAD_LICENSE', message: 'Enter a license key.' }, 400);
  const licenseHash = await hmacHex(`license:${license}`);
  const blobKey = licenseBlobKey(licenseHash);
  const current = await getLicenseRecord(blobKey);
  if (!current?.data) return json({ ok: false, code: 'INVALID_LICENSE', message: 'License record not found.' }, 404);
  await store.delete(blobKey);
  return json({ ok: true, message: 'License deleted permanently.' });
}

export default async (request) => {
  if (request.method === 'OPTIONS') return new Response('', { status: 204, headers: CORS_HEADERS });
  if (request.method !== 'POST') return json({ ok: false, code: 'METHOD_NOT_ALLOWED', message: 'Use POST.' }, 405);
  try {
    const body = await request.json();
    const action = String(body?.action || '');

    if (!process.env.RADILUX_AUTH_SECRET) {
      return json({ ok: false, code: 'SERVER_CONFIG', message: 'RADILUX_AUTH_SECRET is not configured on Netlify.' }, 500);
    }

    if (action === 'activate') return await activate(body.licenseKey, body.phone);
    if (action === 'verify') return await verify(body.token);

    if (action === 'adminGenerate') return await adminGenerate(body, request);
    if (action === 'adminRegister') return await adminRegister(body, request);
    if (action === 'adminImportConfigured') return await adminImportConfigured(request);
    if (action === 'adminList') return await adminList(request);
    if (action === 'adminReset') return await adminReset(body, request);
    if (action === 'adminRevoke') return await adminRevoke(body, request);
    if (action === 'adminRestore') return await adminRestore(body, request);
    if (action === 'adminDelete') return await adminDelete(body, request);

    return json({ ok: false, code: 'BAD_ACTION', message: 'Unsupported license action.' }, 400);
  } catch (e) {
    console.error('Radilux license function error:', e);
    return json({ ok: false, code: 'SERVER_ERROR', message: 'The license server encountered an error. Please try again.' }, 500);
  }
};
