// Unit tests for @moonsox/trust (offline: fetch is mocked; no network).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, createPrivateKey, sign as nodeSign, createHash, generateKeyPairSync } from 'node:crypto';
import fs from 'node:fs';
import * as sdk from '../dist/index.js';

const golden = JSON.parse(fs.readFileSync(new URL('./fixtures/golden-card.json', import.meta.url), 'utf8'));
const API = 'https://trust.moonsox.com/sdk/v1';

// ---- fetch mock: a tiny fake /sdk/v1 ----
const bots = new Map(); // botId -> { publicKeyPem, card? }
let calls = [];
let cardOverride = null;
globalThis.fetch = async (url, init = {}) => {
  url = String(url);
  calls.push({ url, method: init.method || 'GET' });
  if (!url.startsWith(API + '/')) throw new Error('SDK called a non-/sdk/v1 URL: ' + url);
  const p = url.slice(API.length);
  let m;
  const j = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
  if ((m = /^\/bots\/([^/]+)\/jwks$/.exec(p))) {
    const b = bots.get(m[1]);
    if (!b) return j(404, { error: 'not_found' });
    const jwk = createPublicKey(b.publicKeyPem).export({ format: 'jwk' });
    const kid = createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })).digest('base64url');
    return j(200, { keys: [{ kty: 'OKP', crv: 'Ed25519', x: jwk.x, kid, alg: 'EdDSA', use: 'sig' }], moonsox: { botId: m[1] } });
  }
  if ((m = /^\/bots\/([^/]+)\/card$/.exec(p))) {
    if (cardOverride) return j(200, cardOverride);
    return j(404, { error: 'not_found' });
  }
  if (p === '/issuer') return j(200, { issuer: 'https://trust.moonsox.com', keys: [] });
  if (p === '/register') {
    const body = JSON.parse(init.body);
    if (!body.publicKey) return j(400, { error: 'invalid_public_key' });
    return j(201, { botId: 'bot_' + '1'.repeat(24), username: body.username ?? null, created: true, recoveryKeySet: !!body.recoveryKeyHash, extras: { welcome: { x: 1 } } });
  }
  return j(404, { error: 'not_found' });
};

const thumb = (pem) => {
  const jwk = createPublicKey(pem).export({ format: 'jwk' });
  return createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })).digest('base64url');
};

async function freshBot() {
  const k = await sdk.generateKeys();
  const botId = 'bot_' + createHash('sha256').update(k.publicKeyPem).digest('hex').slice(0, 24);
  bots.set(botId, { publicKeyPem: k.publicKeyPem });
  return { ...k, botId };
}

test('exports exactly the six functions (+ MoonsoxError)', () => {
  const fns = Object.keys(sdk).filter((k) => typeof sdk[k] === 'function').sort();
  assert.deepEqual(fns, ['MoonsoxError', 'generateKeys', 'getCard', 'register', 'signRequest', 'verifyCard', 'verifyRequest']);
});

test('generateKeys: standard SPKI / PKCS#8 PEM usable by node:crypto; recovery is independent + thumbprint', async () => {
  const k = await sdk.generateKeys();
  assert.equal(k.recovery, undefined);
  assert.equal(createPublicKey(k.publicKeyPem).asymmetricKeyType, 'ed25519');
  assert.equal(createPrivateKey(k.privateKeyPem).asymmetricKeyType, 'ed25519');
  const sig = nodeSign(null, Buffer.from('x'), createPrivateKey(k.privateKeyPem));
  assert.equal(sig.length, 64);
  const r = await sdk.generateKeys({ recovery: true });
  assert.ok(r.recovery);
  assert.notEqual(r.recovery.publicKeyPem, r.publicKeyPem);
  assert.match(r.recovery.recoveryKeyHash, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(r.recovery.recoveryKeyHash, thumb(r.recovery.publicKeyPem));
  // PEM shape matches what node / openssl export (server normalisation stays stable)
  assert.equal(k.publicKeyPem, createPublicKey(k.publicKeyPem).export({ type: 'spki', format: 'pem' }));
});

test('register: maps the frozen response, raw = extras; errors throw MoonsoxError', async () => {
  const k = await sdk.generateKeys({ recovery: true });
  const r = await sdk.register(k.publicKeyPem, { username: 'x_test', recoveryKeyHash: k.recovery.recoveryKeyHash });
  assert.deepEqual(r, { botId: 'bot_' + '1'.repeat(24), username: 'x_test', created: true, recoveryKeySet: true, raw: { welcome: { x: 1 } } });
  await assert.rejects(() => sdk.register(123), TypeError);
  await assert.rejects(() => sdk.register('not a pem'), TypeError);
});

test('signRequest + verifyRequest round trip, with and without a body', async () => {
  const b = await freshBot();
  const url = 'https://site.example/api/items?page=2';
  const h0 = await sdk.signRequest({ method: 'get', url }, { botId: b.botId, privateKeyPem: b.privateKeyPem });
  assert.deepEqual(Object.keys(h0).sort(), ['Signature', 'Signature-Agent', 'Signature-Input']);
  assert.equal(h0['Signature-Agent'], `"${API}/bots/${b.botId}/jwks"`);
  assert.match(h0['Signature-Input'], /^sig=\("@method" "@authority" "@path" "signature-agent"\);created=\d+;expires=\d+;keyid="[^"]+";alg="ed25519";nonce="[^"]+";tag="web-bot-auth"$/);
  const v0 = await sdk.verifyRequest({ method: 'GET', url, headers: h0 });
  assert.equal(v0.ok, true, JSON.stringify(v0));
  assert.equal(v0.botId, b.botId); assert.equal(v0.keyid, thumb(b.publicKeyPem));
  assert.equal(v0.bodyCovered, false); assert.equal(v0.card, null, 'card unavailable -> card:null (standing unknown)');
  assert.equal(v0.expires - v0.created, 300);

  const body = JSON.stringify({ a: 1, ü: 'ß' });
  const h1 = await sdk.signRequest({ method: 'POST', url, body }, { botId: b.botId, privateKeyPem: b.privateKeyPem });
  assert.equal(h1['Content-Digest'], 'sha-256=:' + createHash('sha256').update(body).digest('base64') + ':');
  const hdrs = new Headers(h1);
  assert.equal((await sdk.verifyRequest({ method: 'POST', url, headers: hdrs, body })).ok, true);
  assert.equal((await sdk.verifyRequest({ method: 'POST', url, headers: h1, body: new TextEncoder().encode(body) })).bodyCovered, true);
  assert.equal((await sdk.verifyRequest({ method: 'POST', url, headers: h1, body: body + 'x' })).reason, 'digest_mismatch');
  assert.equal((await sdk.verifyRequest({ method: 'POST', url, headers: h1 })).reason, 'body_missing');
  // swapping both the body and its digest header breaks the signature
  const evil = 'evil';
  const forged = { ...h1, 'Content-Digest': 'sha-256=:' + createHash('sha256').update(evil).digest('base64') + ':' };
  assert.equal((await sdk.verifyRequest({ method: 'POST', url, headers: forged, body: evil })).reason, 'bad_signature');
});

test('verifyRequest: method, path and host are covered', async () => {
  const b = await freshBot();
  const url = 'https://site.example/a';
  const h = await sdk.signRequest({ method: 'GET', url }, { botId: b.botId, privateKeyPem: b.privateKeyPem });
  assert.equal((await sdk.verifyRequest({ method: 'DELETE', url, headers: h })).reason, 'bad_signature');
  assert.equal((await sdk.verifyRequest({ method: 'GET', url: 'https://site.example/b', headers: h })).reason, 'bad_signature');
  assert.equal((await sdk.verifyRequest({ method: 'GET', url: 'https://other.example/a', headers: h })).reason, 'bad_signature');
  assert.equal((await sdk.verifyRequest({ method: 'GET', url: url + '?q=1', headers: h })).ok, true, '@path excludes the query');
});

test('verifyRequest: failure reasons (never throws)', async () => {
  const b = await freshBot();
  const url = 'https://site.example/a';
  const key = { botId: b.botId, privateKeyPem: b.privateKeyPem };
  const h = await sdk.signRequest({ method: 'GET', url }, key);
  const v = (headers) => sdk.verifyRequest({ method: 'GET', url, headers });
  assert.equal((await v({})).reason, 'missing_headers');
  assert.equal((await v({ ...h, 'Signature-Input': 'garbage' })).reason, 'bad_signature_input');
  assert.equal((await v({ ...h, 'Signature-Input': h['Signature-Input'].replace('web-bot-auth', 'other') })).reason, 'bad_tag');
  assert.equal((await v({ ...h, 'Signature-Agent': '"https://evil.example/v1/bots/' + b.botId + '/jwks"' })).reason, 'unknown_agent');
  assert.equal((await v({ ...h, 'Signature-Agent': '"https://trust.moonsox.com/v1/other/' + b.botId + '"' })).reason, 'unknown_agent');
  assert.equal((await v({ ...h, Signature: 'sig=:' + Buffer.alloc(64).toString('base64') + ':' })).reason, 'bad_signature');
  const other = await freshBot();
  const hOther = await sdk.signRequest({ method: 'GET', url }, { botId: b.botId, privateKeyPem: other.privateKeyPem });
  assert.equal((await v(hOther)).reason, 'key_not_found', 'a key that is not in the named bot JWKS');
  const ghost = await sdk.signRequest({ method: 'GET', url }, { botId: 'bot_' + 'f'.repeat(24), privateKeyPem: b.privateKeyPem });
  assert.equal((await v(ghost)).reason, 'key_not_found');
  // expiry / future
  const old = { ...h };
  const now = Math.floor(Date.now() / 1000);
  old['Signature-Input'] = h['Signature-Input'].replace(/created=\d+;expires=\d+/, `created=${now - 900};expires=${now - 600}`);
  assert.equal((await v(old)).reason, 'expired');
  const fut = { ...h, 'Signature-Input': h['Signature-Input'].replace(/created=\d+;expires=\d+/, `created=${now + 600};expires=${now + 900}`) };
  assert.equal((await v(fut)).reason, 'not_yet_valid');
  await assert.rejects(() => sdk.verifyRequest({ method: 'GET' }), TypeError);
});

test('verifyRequest accepts legacy skill.md-style signers (all 4 Signature-Agent forms), bodyCovered:false', async () => {
  const b = await freshBot();
  const url = 'https://site.example/hello';
  const kid = thumb(b.publicKeyPem);
  for (const agentPath of [`/sdk/v1/bots/${b.botId}/jwks`, `/v1/bots/${b.botId}/jwks`, `/sdk/v1/bots/${b.botId}/.well-known/http-message-signatures-directory`, `/v1/bots/${b.botId}/.well-known/http-message-signatures-directory`]) {
    const agent = `"https://trust.moonsox.com${agentPath}"`;
    const created = Math.floor(Date.now() / 1000);
    const params = `("@authority" "signature-agent");created=${created};keyid="${kid}";alg="ed25519";expires=${created + 300};tag="web-bot-auth"`;
    const base = `"@authority": site.example\n"signature-agent": ${agent}\n"@signature-params": ${params}`;
    const sig = nodeSign(null, Buffer.from(base), createPrivateKey(b.privateKeyPem)).toString('base64');
    const r = await sdk.verifyRequest({ method: 'GET', url, headers: { 'signature-agent': agent, 'signature-input': `sig=${params}`, signature: `sig=:${sig}:` } });
    assert.equal(r.ok, true, agentPath + ' ' + JSON.stringify(r));
    assert.equal(r.bodyCovered, false);
  }
});

test('verifyRequest: JWKS is fetched only from /sdk/v1 on trust.moonsox.com', async () => {
  calls = [];
  const b = await freshBot();
  const url = 'https://site.example/z';
  const h = await sdk.signRequest({ method: 'GET', url }, { botId: b.botId, privateKeyPem: b.privateKeyPem });
  h['Signature-Agent'] = `"https://trust.moonsox.com/v1/bots/${b.botId}/jwks"`;
  await sdk.verifyRequest({ method: 'GET', url, headers: h }); // signature now bad, but fetch path must still be /sdk/v1
  assert.ok(calls.every((c) => c.url.startsWith(API + '/')));
});

test('verifyCard: golden live card verifies offline with the pinned issuer key', async () => {
  const r = await sdk.verifyCard(golden, { maxAgeSec: 1e10 });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.summary.botId, 'bot_7b208c4edcae2ec289792078');
  assert.equal(r.summary.username, 'mel');
  assert.equal(typeof r.summary.bonded, 'boolean');
  assert.equal(r.summary.bonded, golden.bond.status === 'bonded');
  assert.equal(r.card, golden);
  assert.deepEqual(Object.keys(r.summary).sort(), ['amountLamports', 'bondAsOf', 'bondStatus', 'bonded', 'botId', 'didKey', 'mintedAt', 'requiredLamports', 'username']);
});

test('verifyCard: tamper, foreign issuer, stale', async () => {
  const t = structuredClone(golden); t.bond.status = 'bonded'; t.bond.amountLamports = 999999999;
  assert.equal((await sdk.verifyCard(t, { maxAgeSec: 1e10 })).reason, 'card_bad_hash');
  const noSig = structuredClone(golden); delete noSig.signature;
  assert.equal((await sdk.verifyCard(noSig, { maxAgeSec: 1e10 })).reason, 'card_bad_hash');
  const badSig = structuredClone(golden); badSig.signature = Buffer.alloc(64, 1).toString('base64');
  assert.equal((await sdk.verifyCard(badSig, { maxAgeSec: 1e10 })).reason, 'card_bad_signature');
  // re-signed by a key that does not chain to the pinned issuer
  const { privateKey } = generateKeyPairSync('ed25519');
  const fake = structuredClone(golden); delete fake.bundleHash; delete fake.signature;
  fake.exportMeta.exporterDidKey = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  const canon = (v) => v === null || typeof v !== 'object' ? JSON.stringify(v) : Array.isArray(v) ? '[' + v.map(canon).join(',') + ']' : '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  fake.bundleHash = createHash('sha256').update(canon(fake)).digest('hex');
  fake.signature = nodeSign(null, Buffer.from(fake.bundleHash), privateKey).toString('base64');
  assert.equal((await sdk.verifyCard(fake, { maxAgeSec: 1e10 })).reason, 'card_unknown_issuer');
  assert.equal((await sdk.verifyCard(golden, { maxAgeSec: 0 })).reason, 'card_stale');
  await assert.rejects(() => sdk.verifyCard(null), TypeError);
  await assert.rejects(() => sdk.verifyCard(golden, { maxAgeSec: -1 }), TypeError);
});

test('getCard: verifies before returning; a card for another botId is refused; 404 -> card_unavailable', async () => {
  assert.equal((await sdk.getCard('bot_' + 'a'.repeat(24))).reason, 'card_unavailable');
  cardOverride = golden;
  // golden is older than its ttl in CI over time; freshness failing is still a verified refusal
  const r = await sdk.getCard('bot_' + 'a'.repeat(24));
  assert.equal(r.ok, false);
  assert.ok(['card_bad_signature', 'card_stale'].includes(r.reason), r.reason);
  cardOverride = null;
  await assert.rejects(() => sdk.getCard(''), TypeError);
});
