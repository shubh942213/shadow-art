// Predefined security keys. Add/remove lines here and redeploy to issue or revoke access.
const VALID_KEYS = [
  'SHADOW-AB12-CD34',
  'SHADOW-EF56-GH78',
  'SHADOW-IJ90-KL12',
  'SHUBH94' // test key
];

const MAX_ATTEMPTS = 5;

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return resp(405, { ok: false, msg: 'Method not allowed' });
  }

  let key, phone;
  try {
    ({ key, phone } = JSON.parse(event.body || '{}'));
  } catch {
    return resp(400, { ok: false, msg: 'Bad request' });
  }

  key = (key || '').trim().toUpperCase();
  phone = (phone || '').replace(/\D/g, ''); // digits only, so formatting differences don't matter

  if (!key) return resp(400, { ok: false, msg: 'Enter your security key' });
  if (!phone || phone.length < 7) return resp(400, { ok: false, msg: 'Enter a valid phone number' });
  if (!VALID_KEYS.includes(key)) return resp(403, { ok: false, msg: 'Unknown security key' });

  const { getStore, connectLambda } = await import('@netlify/blobs');
  connectLambda(event); // required in Lambda-compatible handlers - Blobs isn't auto-configured otherwise
  const store = getStore('licenses');
  const rec = await store.get(key, { type: 'json' });

  // first-ever activation: bind this key to this phone number
  if (!rec) {
    await store.setJSON(key, { phone, activatedAt: Date.now(), attempts: 0 });
    return resp(200, { ok: true, msg: 'Activated' });
  }

  // already bound: matching phone always gets back in
  if (rec.phone === phone) {
    if (rec.attempts) { rec.attempts = 0; await store.setJSON(key, rec); }
    return resp(200, { ok: true, msg: 'Welcome back' });
  }

  // wrong phone for a key that's already registered to someone else
  if ((rec.attempts || 0) >= MAX_ATTEMPTS) {
    return resp(423, { ok: false, msg: 'Too many failed attempts on this key. It is locked — contact support.' });
  }
  rec.attempts = (rec.attempts || 0) + 1;
  await store.setJSON(key, rec);
  return resp(403, { ok: false, msg: 'This key is already registered to a different phone number.' });
};

function resp(statusCode, obj) {
  return { statusCode, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(obj) };
}
